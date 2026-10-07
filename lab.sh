#!/usr/bin/env bash
# Laboratório local do FileWatch (Linux / macOS / Git Bash).
#
# Tudo acontece dentro desta pasta do projeto:
#   - o monitor só observa ./sandbox (que tem o marcador .filewatch-sandbox);
#   - o simulador só escreve em ./sandbox/victims/run-<timestamp>/;
#   - o estado fica em ./baseline.json e ./alerts.log; os logs do demo em ./target/.
# Nada pede root, nada abre rede, nada roda fora desta pasta.
#
# Uso: ./lab.sh <comando>
#   check    confere Java e Maven
#   test     roda os testes unitários
#   demo     sobe o monitor, roda o simulador e mostra se o alerta HIGH saiu (recomendado)
#   monitor  sobe só o monitor em primeiro plano (Ctrl+C para parar)
#   attack   roda o simulador benigno (use com o monitor aberto em outro terminal)
#   clean    apaga só as pastas geradas pelo simulador
#   reset    clean + apaga baseline.json e alerts.log
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX="$ROOT/sandbox"
JAR="$ROOT/target/filewatch-0.1.0-SNAPSHOT.jar"
SIMULATOR="$ROOT/tools/RansomwareSimulator.java"
ALERTS="$ROOT/alerts.log"
UTF8=(-Dfile.encoding=UTF-8 -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8)
MONITOR_JVM=(-Xmx256m "${UTF8[@]}")   # o monitor não precisa de mais memória que isso
MONITOR_PID=""

cd "$ROOT"

say() { printf '\033[36m==> %s\033[0m\n' "$*"; }
ok() { printf '\033[32m==> %s\033[0m\n' "$*"; }
err() { printf '\033[31m==> %s\033[0m\n' "$*" >&2; }

require_tools() {
  for tool in java mvn; do
    command -v "$tool" >/dev/null || { err "$tool não encontrado no PATH. Instale Java 17+ e Maven 3.9+."; exit 1; }
  done
}

require_sandbox() {
  [[ -f "$SANDBOX/.filewatch-sandbox" ]] || { err "Marcador sandbox/.filewatch-sandbox não encontrado."; exit 1; }
}

build() { say "Compilando (mvn package, sem testes)"; mvn -q -DskipTests package; }

simulator() { java "${UTF8[@]}" "$SIMULATOR" "$SANDBOX" "$@"; }

count_alerts() { if [[ -f "$ALERTS" ]]; then wc -l <"$ALERTS" | tr -d ' '; else echo 0; fi; }

# O "java" do PATH pode ser um atalho (ex.: Oracle javapath no Windows) que abre o java real como filho;
# aí matar o PID do atalho deixaria o monitor órfão. Por isso o demo usa o binário do java.home.
real_java() {
  local home
  home=$(java -XshowSettings:properties -version 2>&1 | sed -n 's/^ *java[.]home *= *//p' | head -n 1 | tr -d '\r')
  if [[ -n "$home" && -x "$home/bin/java" ]]; then echo "$home/bin/java"
  elif [[ -n "$home" && -x "$home/bin/java.exe" ]]; then echo "$home/bin/java.exe"
  else command -v java; fi
}

stop_monitor() {
  if [[ -n "$MONITOR_PID" ]]; then
    kill "$MONITOR_PID" 2>/dev/null || true
    wait "$MONITOR_PID" 2>/dev/null || true
    say "Monitor encerrado. Para apagar os arquivos gerados: ./lab.sh clean"
  fi
}

demo() {
  require_tools; require_sandbox; build
  local log="$ROOT/target/lab-monitor.log"

  # Começa do zero: execuções antigas do simulador e um baseline velho fariam a varredura inicial
  # alertar sobre arquivos de antes, e o cooldown silenciaria o alerta desta execução.
  say "Limpando execuções anteriores e o baseline"
  simulator --clean --confirm
  rm -f "$ROOT/baseline.json" "$ROOT/baseline.json.tmp"
  local before; before=$(count_alerts)
  rm -f "$log"

  say "Subindo o monitor em segundo plano (log: target/lab-monitor.log)"
  "$(real_java)" "${MONITOR_JVM[@]}" -jar "$JAR" >"$log" 2>&1 &
  MONITOR_PID=$!
  trap stop_monitor EXIT

  for _ in $(seq 1 200); do
    grep -q "Varredura inicial" "$log" 2>/dev/null && break
    kill -0 "$MONITOR_PID" 2>/dev/null || { tail -n 30 "$log"; err "O monitor parou na inicialização"; exit 1; }
    sleep 0.3
  done
  grep -q "Varredura inicial" "$log" || { err "O monitor não terminou a varredura inicial"; exit 1; }

  say "Monitor pronto. Rodando o simulador benigno"
  simulator --confirm

  say "Aguardando o alerta"
  local high=""
  for _ in $(seq 1 40); do
    sleep 0.5
    high=$(tail -n +"$((before + 1))" "$ALERTS" 2>/dev/null | grep '"severity":"HIGH"' | head -n 1 || true)
    [[ -n "$high" ]] && break
  done
  echo
  if [[ -n "$high" ]]; then
    ok "PASSOU: alerta HIGH detectado"
    echo "$high" | grep -o '"S[1-4] [^"]*"' | sed 's/^"/    - /; s/"$//'
    echo "    (detalhes em alerts.log)"
  else
    err "FALHOU: nenhum alerta HIGH em 20 s. Veja target/lab-monitor.log"
    exit 1
  fi
}

case "${1:-help}" in
  check) require_tools; java -version; mvn -v | head -n 1; require_sandbox; ok "Ambiente ok" ;;
  test) require_tools; mvn test ;;
  demo) demo ;;
  monitor) require_tools; require_sandbox; build; say "Monitor observando $SANDBOX (Ctrl+C para parar)"; java "${MONITOR_JVM[@]}" -jar "$JAR" ;;
  attack) require_tools; require_sandbox; simulator --confirm ;;
  clean) require_tools; require_sandbox; simulator --clean --confirm ;;
  reset)
    require_tools; require_sandbox; simulator --clean --confirm
    for f in baseline.json baseline.json.tmp alerts.log; do
      if [[ -f "$ROOT/$f" ]]; then rm -- "$ROOT/$f"; say "Removido $f"; fi
    done
    ;;
  *) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//' ;;
esac
