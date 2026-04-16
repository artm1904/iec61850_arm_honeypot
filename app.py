#!/usr/bin/env -S python3 -u
from flask import Flask, render_template, session, request, redirect, url_for, jsonify, send_file
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime

import socket
import json
import subprocess
import time
import sys
import os
import logging
import atexit
import signal
import requests

import libiec61850client
import libiec60870client
from urllib.parse import urlparse

import threading

thread = None
thread_lock = threading.Lock()

tick = 0.001
focus = ''
hosts_info = {}
reset_log = False
async_mode = None
local_svg = True
async_msg = []
async_rpt = {}

# Locks for thread safety
clients_lock = {}
async_lock = threading.Lock()
hosts_info_lock = threading.Lock()

# ─── Simulator API target (docker network IP) ──────────────────────────────
SIMULATOR_URL = os.environ.get('SIMULATOR_URL', 'http://10.0.0.254:5010')

# ─── RBAC roles ─────────────────────────────────────────────────────────────
ROLES = {
    'admin':    {'label': 'Администратор',            'can_control': True,  'can_config': True,  'can_view': True},
    'engineer': {'label': 'Инженер РЗА',              'can_control': True,  'can_config': True,  'can_view': True},
    'operator': {'label': 'Оператор / Диспетчер',     'can_control': True,  'can_config': False, 'can_view': True},
    'auditor':  {'label': 'Аудитор / Наблюдатель',     'can_control': False, 'can_config': False, 'can_view': True},
    'guest':    {'label': 'Гостевой доступ (только просмотр)', 'can_control': False, 'can_config': False, 'can_view': True},
}

# Valid credentials (honeypot — attacker will brute-force around these)
VALID_USERS = {
    'artm1904': {'password': '1904', 'default_role': 'admin'},
}

# Per-session brute-force counter (IP-based)
login_attempts = {}  # ip -> count

# ─── Flask app ──────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'tpot_honeypot_secret_key_arm_1904'

# ─── Honeypot JSON logger ───────────────────────────────────────────────────
def log_honeypot_action(action, details=None, username='unknown', ip='127.0.0.1'):
    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "service": "iec61850_web_hmi",
        "action": action,
        "details": details or {},
        "ip": ip,
        "user": username,
        "session_role": session.get('role', 'none')
    }
    log_file = '/var/log/tpot/vied_events.json'
    if not os.path.exists('/var/log/tpot'):
        log_file = '/tmp/vied_events.json'
    try:
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
    except Exception as e:
        try:
            logger.error(f"Could not write honeypot log: {e}")
        except:
            pass

# ─── Auth decorators ────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*allowed_caps):
    """Check that session role has at least one of the listed capabilities."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            role = session.get('role', 'guest')
            role_info = ROLES.get(role, ROLES['guest'])
            if not any(role_info.get(cap) for cap in allowed_caps):
                log_honeypot_action('access_denied', details={'required': list(allowed_caps), 'role': role},
                                    username=session.get('username', '?'), ip=request.remote_addr)
                return jsonify({'status': 'error', 'msg': 'Недостаточно прав для данной операции.'}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ─── SocketIO ───────────────────────────────────────────────────────────────
socketio = SocketIO(app,
    async_mode="gevent",
    cors_allowed_origins="*",
    allow_upgrades=False,
    transports=["websocket"],
    ping_timeout=30,
    ping_interval=60
)

# logging handler, for sending logs to the client
class socketHandler(logging.StreamHandler):
  def __init__(self, socket):
    logging.StreamHandler.__init__(self)
    self.socket = socket

  def emit(self, record):
    msg = self.format(record)
    self.socket.emit('log_event', {'host':'localhost','data':msg,'clear':0})


# ═══════════════════════════════════════════════════════════════════════════
# HTTP ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@app.route('/', methods=['GET'])
@login_required
def index():
    global reset_log, local_svg
    reset_log = True
    role = session.get('role', 'guest')
    role_info = ROLES.get(role, ROLES['guest'])
    log_honeypot_action('page_view', details={'page': 'index'}, username=session.get('username','?'), ip=request.remote_addr)
    return render_template('index.html',
        local_svg=local_svg,
        async_mode=socketio.async_mode,
        role=role,
        role_info=role_info,
        role_label=role_info['label'],
        username=session.get('username','Гость'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    global login_attempts
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        role     = request.form.get('role', 'operator')
        ip       = request.remote_addr
        ua       = request.headers.get('User-Agent', '')

        # Guest access — no password required
        if role == 'guest':
            session['logged_in'] = True
            session['username'] = 'guest'
            session['role'] = 'guest'
            log_honeypot_action('auth_guest', details={'user_agent': ua}, username='guest', ip=ip)
            return redirect(url_for('index'))

        # Track brute-force attempts per IP
        if ip not in login_attempts:
            login_attempts[ip] = 0
        login_attempts[ip] += 1
        attempt = login_attempts[ip]

        # Log every attempt with maximum detail
        log_honeypot_action('auth_attempt', details={
            'attempted_username': username,
            'attempted_password': password,
            'attempted_role': role,
            'attempt_number': attempt,
            'user_agent': ua,
            'accept_language': request.headers.get('Accept-Language', ''),
            'referer': request.headers.get('Referer', ''),
            'content_length': request.content_length,
        }, username=username, ip=ip)

        # Honeypot logic: first 10 attempts ALWAYS fail, 11th succeeds
        user_record = VALID_USERS.get(username)
        if attempt <= 10:
            # Always deny for first 10 attempts regardless of correctness
            remaining = 10 - attempt
            if remaining > 0:
                error_msg = f'Неверный логин или пароль. Осталось попыток: {remaining}'
            else:
                error_msg = 'Учётная запись временно заблокирована. Повторите попытку.'
            return render_template('login.html', error=error_msg, roles=ROLES)
        else:
            # 11th attempt and beyond — let them in regardless
            session['logged_in'] = True
            session['username'] = username
            session['role'] = role if role in ROLES else 'operator'
            login_attempts[ip] = 0  # reset counter
            log_honeypot_action('auth_success', details={
                'granted_role': session['role'],
                'attempt_number': attempt,
                'user_agent': ua,
            }, username=username, ip=ip)
            return redirect(url_for('index'))

    return render_template('login.html', roles=ROLES)


@app.route('/logout')
def logout():
    log_honeypot_action('logout', username=session.get('username','?'), ip=request.remote_addr)
    session.clear()
    return redirect(url_for('login'))


# ─── Oscillogram (COMTRADE) viewer ──────────────────────────────────────────
@app.route('/api/comtrade/list', methods=['GET'])
@login_required
def comtrade_list():
    """List available COMTRADE files."""
    comtrade_dir = os.path.join(app.static_folder, 'comtrade')
    files = []
    if os.path.isdir(comtrade_dir):
        for fn in sorted(os.listdir(comtrade_dir)):
            if fn.lower().endswith('.cfg'):
                base = fn[:-4]
                dat = base + '.dat'
                if os.path.exists(os.path.join(comtrade_dir, dat)):
                    files.append({'name': base, 'cfg': fn, 'dat': dat})
    log_honeypot_action('comtrade_list', details={'count': len(files)},
                        username=session.get('username','?'), ip=request.remote_addr)
    return jsonify(files)


@app.route('/api/comtrade/read/<basename>', methods=['GET'])
@login_required
def comtrade_read(basename):
    """Read and parse a COMTRADE .cfg/.dat pair, return JSON arrays for plotting."""
    comtrade_dir = os.path.join(app.static_folder, 'comtrade')
    cfg_path = os.path.join(comtrade_dir, secure_filename(basename + '.cfg'))
    dat_path = os.path.join(comtrade_dir, secure_filename(basename + '.dat'))

    log_honeypot_action('comtrade_read', details={'file': basename},
                        username=session.get('username','?'), ip=request.remote_addr)

    if not os.path.exists(cfg_path) or not os.path.exists(dat_path):
        return jsonify({'error': 'Файл не найден'}), 404

    # Parse simple ASCII COMTRADE (IEC 60255-24)
    try:
        channels = []
        sample_count = 0
        with open(cfg_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
        # Line 1: station_name, rec_dev_id, rev_year
        # Line 2: TT, ##A, ##D
        parts = lines[1].strip().split(',')
        total_ch = int(parts[0])
        analog_ch = int(parts[1].replace('A',''))
        for i in range(analog_ch):
            ch_line = lines[2 + i].strip().split(',')
            ch_name = ch_line[1] if len(ch_line) > 1 else f'CH{i}'
            ch_unit = ch_line[4] if len(ch_line) > 4 else ''
            channels.append({'name': ch_name.strip(), 'unit': ch_unit.strip(), 'data': []})

        # Read .dat
        timestamps = []
        with open(dat_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                vals = line.strip().split(',')
                if len(vals) < 2 + analog_ch:
                    continue
                timestamps.append(float(vals[1]))
                for ci in range(analog_ch):
                    channels[ci]['data'].append(float(vals[2 + ci]))
        return jsonify({'channels': channels, 'timestamps': timestamps})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── Proxy to simulator API ────────────────────────────────────────────────
@app.route('/api/sim/<action>', methods=['GET'])
@login_required
@role_required('can_control')
def sim_proxy(action):
    """Proxy simulation commands to the circuit_simulator container."""
    ip = request.remote_addr
    username = session.get('username', '?')
    ua = request.headers.get('User-Agent', '')

    if action == 'play':
        url = f"{SIMULATOR_URL}/play_simulation?delay=0.001&step=10"
    elif action == 'reinit':
        url = f"{SIMULATOR_URL}/reinit"
    elif action == 'init':
        url = f"{SIMULATOR_URL}/init"
    elif action == 'plot_current':
        url = f"{SIMULATOR_URL}/plot_simulation?plot=1"
    elif action == 'plot_voltage':
        url = f"{SIMULATOR_URL}/plot_simulation?plot=2"
    elif action == 'clear_plot':
        url = f"{SIMULATOR_URL}/clear_plot"
    else:
        log_honeypot_action('sim_unknown_action', details={'action': action, 'user_agent': ua}, username=username, ip=ip)
        return jsonify({'status': 'error', 'msg': 'Неизвестная команда.'}), 400

    log_honeypot_action(f'sim_{action}', details={'target_url': url, 'user_agent': ua}, username=username, ip=ip)
    try:
        resp = requests.get(url, timeout=10)
        return jsonify({'status': 'ok', 'msg': f'Команда выполнена: {action}', 'upstream': resp.json()})
    except Exception as e:
        return jsonify({'status': 'error', 'msg': f'Ошибка связи с симулятором: {str(e)}'})


# ─── SocketIO simulation action handler ─────────────────────────────────────
@socketio.on('sim_action', namespace='')
def sim_action(data):
    action = data.get('action')
    filename = data.get('filename', '')
    extra = data.get('extra', {})
    ip_addr = request.remote_addr if request else 'unknown'
    username = session.get('username', 'socket_client') if request else 'unknown'
    ua = request.headers.get('User-Agent', '') if request else ''
    role = session.get('role', 'guest')
    role_info = ROLES.get(role, ROLES['guest'])

    log_honeypot_action(f'sim_action_{action}', details={
        'filename': filename, 'extra': extra, 'user_agent': ua, 'role': role
    }, username=username, ip=ip_addr)

    # Permission check for socket-based actions
    if action in ('start_polling', 'reinit', 'reset_interlocks') and not role_info.get('can_control'):
        return {'status': 'error', 'msg': 'Недостаточно прав для данной операции.'}
    if action in ('load_config',) and not role_info.get('can_config'):
        return {'status': 'error', 'msg': 'Недостаточно прав для загрузки конфигурации.'}

    if action == "load_config":
        msg = f"Конфигурация «{filename}» успешно загружена. Применение уставок..."
    elif action == "start_polling":
        # Actually hit the simulator
        try:
            resp = requests.get(f"{SIMULATOR_URL}/play_simulation?delay=0.001&step=10", timeout=10)
            upstream = resp.json()
            msg = f"Опрос оборудования запущен. Симулятор: {upstream.get('run','?')}"
        except Exception as e:
            msg = f"Опрос запущен (локально). Ошибка связи с симулятором: {str(e)}"
    elif action == "reinit":
        try:
            resp = requests.get(f"{SIMULATOR_URL}/reinit", timeout=10)
            upstream = resp.json()
            msg = f"Реинициализация выполнена. Симулятор: {upstream.get('reinit','?')}"
        except Exception as e:
            msg = f"Реинициализация (локально). Ошибка связи: {str(e)}"
    elif action == "reset_interlocks":
        msg = "Жёсткая блокировка успешно сброшена. Блинкеры деактивированы."
    elif action == "read_oscillograms":
        msg = "Запрос осциллограмм отправлен. Используйте панель «Осциллограммы» для выбора."
    elif action == "generate_report":
        msg = "Формирование отчёта начато. По завершении файл будет доступен для скачивания."
    elif action == "diagnostic":
        msg = "Самодиагностика оборудования... Все модули исправны. Связь: OK."
    elif action == "sync_time":
        msg = f"Синхронизация времени выполнена. Сервер: {datetime.utcnow().isoformat()}Z"
    elif action == "read_journal":
        msg = "Журнал аварийных событий запрошен."
    else:
        msg = "Команда успешно принята к исполнению."
    return {'status': 'ok', 'msg': msg}


# ─── Generic button click logger (catch-all for UI telemetry) ────────────
@socketio.on('ui_interaction', namespace='')
def ui_interaction(data):
    ip_addr = request.remote_addr if request else 'unknown'
    username = session.get('username', '?') if request else 'unknown'
    ua = request.headers.get('User-Agent', '') if request else ''
    log_honeypot_action('ui_interaction', details={
        'element': data.get('element', '?'),
        'action': data.get('action', 'click'),
        'value': data.get('value', ''),
        'user_agent': ua,
        'page_url': data.get('page_url', ''),
        'viewport': data.get('viewport', ''),
        'timestamp_client': data.get('ts', ''),
    }, username=username, ip=ip_addr)
    return {'status': 'logged'}


# ═══════════════════════════════════════════════════════════════════════════
# SocketIO events (existing IEC 61850 / 60870 client interface)
# ═══════════════════════════════════════════════════════════════════════════

@socketio.on('connect', namespace='')
def test_connect():
    global thread
    with thread_lock:
        if thread is None:
            thread = socketio.start_background_task(worker)

@socketio.on('get_page_data', namespace='')
def get_page_data(data):
  emit('page_reload', {'data': ""})

@socketio.on('set_focus', namespace='')
def set_focus(data):
  global focus, hosts_info
  focus = data
  with hosts_info_lock:
      if focus in hosts_info and 'data' in hosts_info[focus]:
        socketio.emit('info_event', hosts_info[focus]['data'] )
      else:
        socketio.emit('info_event', "" )
  emit('select_tab_event', {'host_name': focus})

@socketio.on('read_value', namespace='')
def read_value(data):
  logger.debug("read value:" + str(data['id'])  )
  log_honeypot_action('mms_read', details={'ref': data['id']},
                      username=session.get('username','?'), ip=request.remote_addr if request else '?')
  uri = urlparse(data['id'])
  if uri.scheme in clients:
      with clients_lock[uri.scheme]:
          return clients[uri.scheme].ReadValue(data['id'])
  return {}, -1

@socketio.on('write_value', namespace='')
def write_value(data):
  logger.debug("write value:" + str(data['value']) + ", element:" + str(data['id']) )
  log_honeypot_action('mms_write', details={'ref': data['id'], 'value': data['value']},
                      username=session.get('username','?'), ip=request.remote_addr if request else '?')
  uri = urlparse(data['id'])
  if uri.scheme in clients:
      with clients_lock[uri.scheme]:
          retValue = clients[uri.scheme].registerWriteValue(str(data['id']),str(data['value']))
      if uri.scheme == 'iec61850':
          if retValue > 0:
              return retValue, libiec61850client.IedClientError(retValue).name
          if retValue == 0:
              return retValue, "no error"
          return retValue, "general error"
      else:
          return retValue, "no error" if retValue == 0 else "general error"
  return -1, "unsupported scheme"

@socketio.on('operate', namespace='')
def operate(data):
  logger.debug("operate:" + str(data['id']) + " v:" + str(data['value'])  )
  log_honeypot_action('mms_operate', details={'ref': data['id'], 'value': data['value']},
                      username=session.get('username','?'), ip=request.remote_addr if request else '?')
  uri = urlparse(data['id'])
  if uri.scheme == 'iec61850':
      with clients_lock['iec61850']:
          return clients['iec61850'].operate(str(data['id']),str(data['value']))
  if uri.scheme == 'iec60870':
      with clients_lock['iec60870']:
          return clients['iec60870'].operate(str(data['id']),str(data['value']))
  return -1, "Operation not supported for this protocol"

@socketio.on('select', namespace='')
def select(data):
  logger.debug("select:" + str(data['id'])  )
  log_honeypot_action('mms_select', details={'ref': data['id']},
                      username=session.get('username','?'), ip=request.remote_addr if request else '?')
  uri = urlparse(data['id'])
  if uri.scheme == 'iec61850':
      with clients_lock['iec61850']:
          return clients['iec61850'].select(str(data['id']),str(data['value']))
  if uri.scheme == 'iec60870':
      with clients_lock['iec60870']:
          return clients['iec60870'].select(str(data['id']),str(data['value']))
  return -1, "Operation not supported for this protocol"

@socketio.on('cancel', namespace='')
def cancel(data):
  logger.debug("cancel:" + str(data['id'])  )
  uri = urlparse(data['id'])
  if uri.scheme == 'iec61850':
      with clients_lock['iec61850']:
          return clients['iec61850'].cancel(str(data['id']))
  return -1, "Operation not supported for this protocol"

@socketio.on('register_datapoint', namespace='')
def register_datapoint(data):
  logger.debug("register datapoint:" + str(data) )
  uri = urlparse(data['id'])
  if uri.scheme in clients:
      with clients_lock[uri.scheme]:
          clients[uri.scheme].registerReadValue(str(data['id']))
  return 0

@socketio.on('register_datapoint_finished', namespace='')
def register_datapoint_finished(data):
  with clients_lock['iec61850']:
      ieds = clients['iec61850'].getRegisteredIEDs()
  for key in ieds:
    tupl = key.split(':')
    hostname = tupl[0]
    emit('log_event', {'host':key,'data':'[+] adding IED info','clear':1})

  with clients_lock['iec60870']:
      rtus = clients['iec60870'].getRegisteredRTUs()
  for key in rtus:
    tupl = key.split(':')
    hostname = tupl[0]
    emit('log_event', {'host':key,'data':'[+] adding RTU info','clear':1})


# ═══════════════════════════════════════════════════════════════════════════
# Callbacks & background worker (unchanged logic)
# ═══════════════════════════════════════════════════════════════════════════

def readvaluecallback61850(key,data):
  logger.debug("iec61850 callback: %s - %s" % (key,data))
  socketio.emit("svg_value_update_event",{ 'element' : key, 'data' : data })

def readvaluecallback104(key,data):
  logger.debug("104 callback: %s - %s" % (key,data))
  socketio.emit("svg_value_update_event",{ 'element' : key, 'data' : data })

def cmdTerm_cb(msg):
  with async_lock:
      async_msg.append(msg)

def Rpt_cb(key, value):
  with async_lock:
      async_rpt[key] = value

def process_info_event(loaded_json, prnitems):
  global focus, hosts_info
  ihost = loaded_json['host']
  with hosts_info_lock:
      if not ihost in hosts_info:
        hosts_info[ihost] = {}
      hosts_info[ihost]['last'] = loaded_json['last']
      hosts_info[ihost]['data'] = prnitems
  if ihost==focus:
    socketio.emit('info_event', prnitems)


def printItemsIEC60870(dictObjs):
  dictObj = dictObjs['data']
  el = 'Обновлено: '+str(time.strftime("%a, %d %b %Y %H:%M:%S",time.localtime(dictObjs['last'])))+'<br><br>'
  el += '<table id="CurrentRTUModel" style="width:100%; border: 1px solid white; border-collapse: collapse;"><tr>'
  el += '<th>ASDU</th><th>IOA</th><th>Значение</th></tr>\n'
  for element in dictObj:
      if 'value' in dictObj[element]:
        id = "iec60870://" + dictObjs['host'] + "/" + str(dictObj[element]['value']) + "/" + str(element)
        el += ('<tr id="'+id+'"><td style="border: 1px solid white; border-collapse: collapse;"> ' + str(dictObj[element]['ASDU']) + '</td><td style="border: 1px solid white; border-collapse: collapse;"> ' + str(element) + '</td><td style="border: 1px solid white; border-collapse: collapse;">'+ str(dictObj[element]['value']) + '</td></tr>')
  el += ('</table>\n')
  return el


def printItemsIEC61850(dictObjs):
  dictObj = dictObjs['data']
  el = 'Обновлено: '+str(time.strftime("%a, %d %b %Y %H:%M:%S",time.localtime(dictObjs['last'])))+'<br><br>'
  el += '<table id="CurrentIEDModel" style="width:100%; border: 1px solid white; border-collapse: collapse;"><tr>'
  el += '<th>Ссылка</th><th>Значение</th></tr>\n'

  def printrefs(model, ref="", depth=0):
    _ref = ""
    row = ""
    for element in model:
      if depth == 0:
        _ref = element
      elif depth == 1:
        _ref = ref + "/" + element
      elif depth > 1:
        _ref = ref + "." + element
      if 'value' in model[element] and 'FC' in model[element]:
        id = "iec61850://" + dictObjs['host'] + "/" + _ref
        row += ('<tr id="'+id+'"><td style="border: 1px solid white; border-collapse: collapse;">['+ model[element]['FC'] + '] ' + _ref + '</td><td style="border: 1px solid white; border-collapse: collapse;">'+ model[element]['value']+ '</td></tr>')
      else:
        row += printrefs(model[element],_ref, depth + 1)
    return row

  el += printrefs(dictObj)
  el += ('</table>\n')
  return el


def worker():
  global focus, hosts_info, reset_log
  socketio.sleep(0.1)
  logger.info("worker treat started")
  while True:
    socketio.sleep(tick)
    if reset_log == True:
      socketio.sleep(0.5)
      focus = ''
      reset_log = False
      socketio.sleep(0.5)
    socketio.sleep(1)
    for scheme, c in clients.items():
        with clients_lock[scheme]:
            c.poll()
    logger.debug("values polled")
    with clients_lock['iec61850']:
        ieds = clients['iec61850'].getRegisteredIEDs()
    for key in ieds:
      tupl = key.split(':')
      hostname = tupl[0]
      port = None
      if len(tupl) > 1 and tupl[1] != "":
        port = int(tupl[1])
      with clients_lock['iec61850']:
          model = clients['iec61850'].getDatamodel(hostname=hostname, port=port)
      loaded_json = {'host': key, 'data': model, 'last': time.time()}
      process_info_event(loaded_json, printItemsIEC61850(loaded_json))
    with clients_lock['iec60870']:
        rtus = clients['iec60870'].getRegisteredRTUs()
    for key in rtus:
      tupl = key.split(':')
      hostname = tupl[0]
      port = None
      if len(tupl) > 1 and tupl[1] != "":
        port = int(tupl[1])
      with clients_lock['iec60870']:
          model = clients['iec60870'].getIOA_list(hostname=hostname, port=port)
      loaded_json = {'host': key, 'data': model, 'last': time.time()}
      process_info_event(loaded_json, printItemsIEC60870(loaded_json))
    while True:
      with async_lock:
          if len(async_msg) == 0:
              break
          msg = async_msg.pop(0)
      logger.info(msg)
    with async_lock:
        rpt_keys = list(async_rpt.keys())
    for key in rpt_keys:
      with async_lock:
          if key in async_rpt:
              val = async_rpt.pop(key)
          else:
              continue
      socketio.emit("svg_value_update_event",{ 'element' : key, 'data' : val })
      logger.debug("%s updated via report" % key)


def teardown():
    logger.info("received kill signal")
    for _client in clients.values():
      _client.stop_worker()
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    os.kill(os.getpid(), signal.SIGINT)

atexit.register(teardown)
signal.signal(signal.SIGINT, lambda *args: teardown())
signal.signal(signal.SIGTERM, lambda *args: teardown())

if __name__ == '__main__':
  logger = logging.getLogger('webserver')
  logging.basicConfig(format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
    level=logging.INFO)

  shm = socketHandler(socketio)
  shm.setLevel(logging.INFO)
  fmm = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
  shm.setFormatter(fmm)
  logger.addHandler(shm)

  if len(sys.argv) > 1 and sys.argv[1] == "-nD":
    local_svg = False

  logger.info("started")
  clients = {
      'iec61850': libiec61850client.iec61850client(readvaluecallback61850, logger, cmdTerm_cb, Rpt_cb),
      'iec60870': libiec60870client.IEC60870_5_104_client(readvaluecallback104,logger)
  }
  clients_lock = {
      'iec61850': threading.Lock(),
      'iec60870': threading.Lock()
  }
  socketio.run(app, host="0.0.0.0", use_reloader=False, allow_unsafe_werkzeug=True)
