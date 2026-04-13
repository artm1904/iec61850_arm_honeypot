#!/bin/bash

# 1. Запоминаем текущую рабочую директорию (WORKDIR из Dockerfile)
ORIGINAL_DIR=$(pwd)

# 2. Запускаем Beelzebub в фоновом режиме (&)
cd /opt/beelzebub
./main &

# 3. Возвращаемся в исходную директорию основного приложения
cd "$ORIGINAL_DIR"

# 4. Запускаем основное приложение (переданное через CMD/command)
exec "$@"
