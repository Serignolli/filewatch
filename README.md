# FileWatch

[![CI](https://github.com/serignolli/filewatch/actions/workflows/ci.yml/badge.svg)](https://github.com/serignolli/filewatch/actions/workflows/ci.yml)
![Java 17+](https://img.shields.io/badge/Java-17%2B-blue)
![Spring Boot 3.5](https://img.shields.io/badge/Spring%20Boot-3.5-6db33f)
[![Licença MIT](https://img.shields.io/badge/licen%C3%A7a-MIT-lightgrey)](LICENSE)

Monitor de integridade de arquivos com **detecção comportamental de ransomware**, em Java 17 + Spring Boot.

Ele observa **uma única pasta**, recalcula hash e entropia **só do arquivo que mudou**, compara com o estado anterior (baseline) e decide, numa janela de 10 segundos, se o padrão das mudanças tem cara de ataque. Vem com um **simulador benigno** para você provocar o alerta na sua própria máquina, sem risco.

**Site com a explicação visual e bancadas interativas:** https://serignolli.github.io/filewatch/

> [!NOTE]
> **Pesquisa e estudo realizados em 2026.** As técnicas de ransomware, as defesas, as referências citadas e as versões usadas (Java 17, Spring Boot 3.5) refletem o que se sabia e usava nesse ano. Se você está lendo isto bem depois, confira se algo mudou antes de tomar as conclusões como atuais.

> [!IMPORTANT]
> Projeto de estudo e portfólio. **Não** é antivírus, não tem driver de kernel e não substitui um AV/EDR nem backup. A defesa que de fato recupera seus dados continua sendo **backup offline e versionado**.

---

## Sumário

- [Teste em 1 minuto](#teste-em-1-minuto)
- [Por que é seguro rodar](#por-que-é-seguro-rodar)
- [Como funciona](#como-funciona)
- [Roteiro de testes manuais](#roteiro-de-testes-manuais)
- [O simulador benigno](#o-simulador-benigno)
- [Configuração](#configuração)
- [Ambiente controlado (recomendado)](#ambiente-controlado-recomendado)
- [Problemas comuns](#problemas-comuns)
- [Critérios de aceitação e testes](#critérios-de-aceitação-e-testes)
- [Limitações](#limitações)
- [Estrutura do repositório](#estrutura-do-repositório)

---

## Teste em 1 minuto

**Requisitos:** Java 17+ e Maven 3.9+ no `PATH`. Não precisa de administrador nem de internet depois que as dependências do Maven forem baixadas.

```bash
git clone https://github.com/serignolli/filewatch.git
cd filewatch
```

```bash
# Windows (cmd ou PowerShell)
.\lab.cmd demo

# Linux / macOS / Git Bash
./lab.sh demo
```

O `demo` faz tudo sozinho:

1. compila o projeto (`mvn package`);
2. limpa execuções anteriores do simulador e o baseline;
3. sobe o monitor em segundo plano observando `./sandbox`;
4. roda o simulador benigno;
5. confere se saiu um alerta `HIGH` e encerra o monitor.

Resultado esperado:

```
==> Monitor pronto. Rodando o simulador benigno
[1/4] 40 vítimas criadas. Aguardando 5s para o baseline...
[2/4] Conteúdo sobrescrito com bytes aleatórios.
[3/4] Arquivos renomeados para .encrypted.
[4/4] Nota de resgate fake criada. Fim.

==> PASSOU: alerta HIGH detectado
    - S1 modificação em massa: 40 arquivos alterados em 10s (limiar 30)
    - S2 salto de entropia: 10 arquivos foram para >= 7,5 bits/byte (+2,0 ou mais) em 10s (limiar 10)
```

> **Por que o alerta não cita S3 (extensão) nem S4 (nota de resgate)?** O `HIGH` já sai na sobrescrita, com S1 + S2. A renomeação e a nota chegam segundos depois, dentro do *cooldown* de 30 s que silencia alertas repetidos. É o comportamento esperado.

### Todos os comandos do laboratório

| Comando | O que faz |
|---|---|
| `check` | Confere Java, Maven e o marcador do sandbox. |
| `test` | Roda os 33 testes unitários (usam pastas temporárias e não sobem o Spring). |
| `demo` | Teste de ponta a ponta com o jar real. Imprime `PASSOU` ou `FALHOU`. |
| `monitor` | Sobe só o monitor em primeiro plano, para acompanhar o log (Ctrl+C para parar). |
| `attack` | Roda só o simulador. Use com o `monitor` aberto em outro terminal. |
| `clean` | Apaga só as pastas que o simulador gerou. |
| `reset` | `clean` + apaga `baseline.json` e `alerts.log`. |

---

## Por que é seguro rodar

Um projeto que simula ransomware precisa provar que não é ransomware. Tudo fica dentro da pasta do projeto, e as proteções estão **no código** (a maioria tem teste automatizado):

| Camada | O que garante |
|---|---|
| Marcador `.filewatch-sandbox` | Monitor **e** simulador só aceitam uma pasta que tenha esse arquivo. Um caminho digitado errado é recusado na inicialização. |
| Recusas fixas | Raiz de disco, a pasta home e qualquer pasta que contenha a home são recusadas pelos dois. |
| Caminho canônico | `toRealPath()` resolve `..`, symlinks e junctions do Windows. Nada fora do sandbox é lido ou escrito. |
| Monitor só lê | Nunca executa, move ou apaga arquivos observados. Escreve só `baseline.json` e `alerts.log`, fora do sandbox. |
| Simulador em *dry run* por padrão | Sem `--confirm` ele só mostra o plano, sem escrever nada. |
| Pasta nova por execução | O simulador escreve só em `sandbox/victims/run-<timestamp>/`, criada por ele naquele momento, e só nos arquivos que ele mesmo criou (`CREATE_NEW`, sem seguir links, sem substituir destino). |
| Nenhuma criptografia | Sobrescreve arquivos descartáveis com bytes de `SecureRandom`. Não existe chave nem "decifrar". Sem rede, sem processos filhos, sem persistência. |
| Limpeza conservadora | `--clean` só apaga pastas `run-<timestamp>` que contêm **exclusivamente** arquivos com os nomes que o simulador gera. Qualquer outro arquivo faz a pasta ser preservada. |
| Sem privilégios | Roda com o usuário comum. A JVM do monitor é limitada a 256 MB. |

Mesmo assim, a postura recomendada para qualquer teste com simulação de malware é usar um [ambiente controlado](#ambiente-controlado-recomendado).

---

## Como funciona

### A ideia

Antivírus tradicional reconhece malware por **assinatura**, o que não pega variantes novas. Mas todo ransomware de criptografia precisa fazer a mesma coisa para cumprir o objetivo (MITRE ATT&CK [T1486](https://attack.mitre.org/techniques/T1486/)): abrir muitos arquivos, trocar o conteúdo por dados cifrados, em geral renomear e deixar uma nota de resgate. Esse **comportamento** deixa rastros mensuráveis:

- **Volume:** dezenas de arquivos alterados em segundos.
- **Aleatoriedade:** dado cifrado tem entropia perto de 8 bits/byte; texto fica perto de 4,5.
- **Nomes:** extensões como `.locked`/`.encrypted` e arquivos como `README_DECRYPT.txt`.

### Arquitetura

Orientada a eventos com o `ApplicationEventPublisher` do Spring. Quem publica não conhece quem consome.

```
FolderWatcher ──FileChangedEvent──▶ FileAnalyzer (@Async) ──FileAnalyzedEvent──▶ RansomwareDetector ──RansomwareSuspectedEvent──▶ AlertListener
 (WatchService,                      (SHA-256 + entropia,                          (janela deslizante,                               (log + alerts.log)
  debounce)                           baseline)                                     4 sinais, cooldown)
```

1. **`FolderWatcher`** registra a pasta e todas as subpastas (o `WatchService` do Java não é recursivo), junta rajadas de eventos do mesmo arquivo por 300 ms e publica `FileChangedEvent`.
2. **`FileAnalyzer`** roda num pool próprio. Lê o arquivo **uma vez**, em blocos de 64 KB: o mesmo laço alimenta o SHA-256 e a contagem de bytes da entropia. Se o hash não mudou, para ali.
3. **`RansomwareDetector`** guarda os eventos dos últimos 10 s e avalia os quatro sinais a cada evento novo.
4. **`AlertListener`** loga o alerta e grava uma linha JSON em `alerts.log`. Não toca em arquivo nenhum.

| Pacote | Conteúdo |
|---|---|
| `config` | `FileWatchProperties` (`filewatch.*`), `AsyncConfig` (pool `analyzer-*`, `Clock`) |
| `watcher` | `FolderWatcher`: registra a árvore toda, faz debounce e trata `OVERFLOW` |
| `analysis` | `FileAnalyzer`, `Baseline` (JSON), `EntropyCalculator`, eventos |
| `detection` | `RansomwareDetector`, `DetectionWindow`, severidade |
| `alert` | `AlertListener`: loga e grava uma linha JSON por alerta |
| `security` | `PathGuard`: confinamento via `toRealPath()` (bloqueia `..` e symlinks para fora) |
| `tools/` | `RansomwareSimulator.java`: simulador **benigno** e independente, fora do build |

### Entropia de Shannon

```
H = − Σ p(x) · log₂ p(x)    para x = 0 … 255    →    0 ≤ H ≤ 8 bits/byte
```

| Tipo de conteúdo | Entropia típica |
|---|---|
| Arquivo de zeros, logs repetitivos | 0 – 2 |
| Texto, código-fonte, CSV, JSON | 4 – 5,5 |
| Executáveis, PDFs sem compressão | 5 – 6,5 |
| ZIP, JPEG, MP4, DOCX | 7,5 – 7,99 |
| Dados cifrados (AES, ChaCha20) | ≈ 7,99 |

Como arquivos comprimidos já têm entropia alta, o detector não olha só o valor absoluto: exige que o arquivo **suba** de entropia em relação ao baseline. A entropia é calculada sobre os primeiros 256 KB de cada arquivo.

### Os quatro sinais

| Sinal | Dispara quando (na janela de `window-seconds`) |
|---|---|
| **S1** modificação em massa | nº de arquivos com conteúdo alterado ≥ `mass-modification-threshold` (30) |
| **S2** salto de entropia | nº de arquivos com entropia ≥ `entropy-absolute-min` (7,5) **e** subida ≥ `entropy-delta-min` (2,0) ≥ `entropy-spike-count` (10) |
| **S3** extensão suspeita | algum arquivo criado/renomeado com extensão em `suspicious-extensions` |
| **S4** nota de resgate | algum nome casa com `ransom-note-patterns` |

**1 sinal gera `WARNING`; 2 ou mais geram `HIGH`.** Depois de um `HIGH`, os alertas ficam silenciados por `alert-cooldown-seconds` (30 s). Um `WARNING` com exatamente os mesmos sinais do anterior também fica silenciado.

A combinação é o que reduz falso positivo: copiar 60 fotos para a pasta dispara S1, mas não S2 (eram arquivos novos, sem entropia anterior para subir), então fica em `WARNING`.

### Decisões que valem destacar

- **Uma leitura por arquivo:** o mesmo laço de blocos alimenta o SHA-256 (arquivo inteiro) e a entropia (só os primeiros `sampling-bytes`).
- **Varredura incremental no start:** arquivo com mesmo tamanho e mtime do baseline é *cache hit* e não é re-hasheado. O log mostra `Varredura inicial: N arquivos, X cache hits, ...`.
- **Primeira execução não alerta:** sem baseline no disco, a varredura só constrói o baseline. Senão todos os arquivos seriam "novos" e o S1 dispararia.
- **O watcher nunca espera por hash:** a thread `folder-watcher` só anota eventos, a `watch-debounce` publica e a análise roda no pool `analyzer-*`. Com a fila cheia, `CallerRunsPolicy` aplica backpressure em vez de descartar eventos.
- **Baseline salvo de forma atômica** (arquivo temporário + move). Um baseline corrompido não derruba o monitor: ele começa vazio e registra o erro.

A especificação completa está em [`SPEC-filewatch.md`](SPEC-filewatch.md).

---

## Roteiro de testes manuais

Para ver o monitor reagindo em tempo real, use dois terminais na raiz do projeto.

**Terminal 1: monitor**

```bash
.\lab.cmd reset      # ou ./lab.sh reset   (começa sem baseline e sem alertas)
.\lab.cmd monitor    # ou ./lab.sh monitor
```

Espere a linha `Varredura inicial (criando baseline): ...`. A partir daí, o monitor está ouvindo `./sandbox`.

**Terminal 2: ataque simulado**

```bash
.\lab.cmd attack     # ou ./lab.sh attack
```

No terminal 1 aparece primeiro um `[WARNING]` (só S1, quando o 30º arquivo é criado) e, segundos depois, o `[HIGH]` com S1 + S2. Cada alerta também vira uma linha JSON em `alerts.log`.

### Experimentos à mão

Com o monitor rodando, crie e edite arquivos dentro de `sandbox/` (fora de `victims/`, ou numa subpasta sua):

| Experimento | Resultado esperado |
|---|---|
| Criar e editar 1 ou 2 arquivos `.txt` | Nenhum alerta. Uso normal fica longe dos limiares. |
| Criar `sandbox/teste.locked` | `WARNING` com S3. |
| Criar `sandbox/how_to_decrypt.txt` | `WARNING` com S4. |
| Fazer os dois acima em menos de 10 s | `HIGH` (S3 + S4). |
| Repetir logo depois de um `HIGH` | Silêncio: cooldown de 30 s. |
| Parar o monitor (Ctrl+C) e subir de novo | Log mostra *cache hits*: arquivos sem mudança não são re-hasheados. |
| `java -jar target/filewatch-0.1.0-SNAPSHOT.jar --filewatch.monitored-path=<sua home>` | O monitor **recusa** a pasta e não inicia. |

Para limpar no fim: `lab clean` (só os arquivos do simulador) ou `lab reset` (também baseline e alertas). Arquivos que você criou à mão em `sandbox/` você apaga à mão.

---

## O simulador benigno

[`tools/RansomwareSimulator.java`](tools/RansomwareSimulator.java) reproduz o **comportamento** de um ransomware sem criptografar nada. As invariantes de segurança estão documentadas e verificadas no topo do arquivo. Roda direto com `java`, sem compilar:

```bash
java tools/RansomwareSimulator.java ./sandbox                    # dry run: só mostra o plano
java tools/RansomwareSimulator.java ./sandbox --confirm          # executa
java tools/RansomwareSimulator.java ./sandbox --clean            # lista o que apagaria
java tools/RansomwareSimulator.java ./sandbox --clean --confirm  # limpa as execuções
```

| Etapa | O que faz | Sinal que provoca |
|---|---|---|
| 1 | Cria 40 relatórios de texto (16 KB cada) em `sandbox/victims/run-<timestamp>/` | (S1 por criação) |
| 2 | Espera 5 s para o monitor registrá-los no baseline com entropia baixa | — |
| 3 | Sobrescreve todos com bytes aleatórios | S1 + S2 |
| 4 | Renomeia para `.encrypted` | S3 |
| 5 | Cria `README_DECRYPT.txt` | S4 |

Opções: `--files N` (padrão 40), `--settle-seconds S` (padrão 5), `--pause-millis M` (padrão 1500).

---

## Configuração

Tudo fica em [`src/main/resources/application.yml`](src/main/resources/application.yml) e pode ser sobrescrito na linha de comando (`--filewatch.<chave>=<valor>`):

```yaml
filewatch:
  monitored-path: ./sandbox            # ÚNICA pasta observada
  require-sandbox-marker: true         # só aceita pasta com o arquivo .filewatch-sandbox
  baseline-file: ./baseline.json
  alerts-file: ./alerts.log            # um alerta por linha, em JSON
  sampling-bytes: 262144               # 256 KB para o cálculo de entropia
  debounce-millis: 300
  detection:
    window-seconds: 10
    mass-modification-threshold: 30
    entropy-spike-count: 10
    entropy-absolute-min: 7.5
    entropy-delta-min: 2.0
    alert-cooldown-seconds: 30
```

Rodando o jar direto (a partir da raiz do projeto, porque os caminhos são relativos):

```bash
mvn package
java -jar target/filewatch-0.1.0-SNAPSHOT.jar
java -jar target/filewatch-0.1.0-SNAPSHOT.jar --filewatch.detection.window-seconds=30
```

Para observar uma pasta real, fora do laboratório, use `--filewatch.require-sandbox-marker=false`. O monitor continua só lendo, mas home e raiz de disco continuam recusadas.

> Não copie o arquivo `.filewatch-sandbox` para pastas com arquivos reais: ele é o que autoriza o simulador a escrever ali.

---

## Ambiente controlado (recomendado)

O laboratório foi feito para ser seguro na sua máquina, mas **testar comportamento de malware, mesmo simulado, pede um ambiente controlado**. É a postura correta e permite calibrar limiares à vontade.

| Opção | Quando usar |
|---|---|
| **VM com snapshot** (VirtualBox, Hyper-V, VMware, UTM) | Isolamento total. Instale Java 17 + Maven, clone o repositório, tire um snapshot e restaure depois de cada rodada. |
| **Windows Sandbox** (Windows Pro/Enterprise) | VM descartável nativa: tudo some ao fechar. |
| **Contêiner Docker** com `eclipse-temurin:17` + Maven | Rápido e descartável no Linux/macOS (o `WatchService` funciona normalmente em volumes internos do contêiner). |
| **Pasta do projeto na própria máquina** | Teste básico. As proteções do código confinam tudo a `./sandbox`. |

Roteiro na VM: snapshot → `lab demo` → confira o `HIGH` → ajuste limiares → restaure o snapshot → repita.

---

## Problemas comuns

| Sintoma | Causa e solução |
|---|---|
| `java`/`mvn não encontrado no PATH` | Instale Java 17+ (ex.: Eclipse Temurin) e Maven 3.9+ e abra um terminal novo. Confira com `lab check`. |
| PowerShell bloqueia `lab.ps1` | Use `.\lab.cmd`, que roda o script só para aquele processo, sem mudar a política do sistema. |
| `./lab.sh: Permission denied` | `chmod +x lab.sh` ou rode `bash lab.sh demo`. |
| `Marcador .filewatch-sandbox não encontrado` | Rode a partir da raiz de um clone completo do projeto. |
| `FALHOU: nenhum alerta HIGH em 20 s` | Veja `target/lab-monitor.log`. Em máquinas lentas ou antivírus agressivo, a sobrescrita pode passar de 10 s: aumente `window-seconds`. |
| Um alerta aparece logo no start | O monitor foi encerrado à força e o baseline não foi salvo, então arquivos antigos parecem novos. Rode `lab reset`. |
| Avisos `sun.misc.Unsafe` no build | Vêm do próprio Maven em JDKs recentes. Não afetam o projeto. |

---

## Critérios de aceitação e testes

```bash
mvn test     # 33 testes unitários; usam @TempDir e não sobem o contexto Spring
```

| Critério | Verificação |
|---|---|
| Só reage dentro de `monitored-path` | `PathGuardTest`, `FileAnalyzerTest.filesOutsideTheSandboxAreIgnored` |
| Monitor recusa pasta sem marcador, home e raiz | `PathGuardTest.withMarkerRequired*`, `PathGuardTest.refusesHomeAndFoldersThatContainIt` |
| Fluxo completo gera `HIGH` | `lab demo` (ponta a ponta com o jar real; roda também no CI) |
| Segundo start não re-hasheia inalterados | `FileAnalyzerTest.secondStartDoesNotRehashUnchangedFiles` + log de cache hits |
| Texto sobrescrito com aleatórios > 7,5 | `FileAnalyzerTest.textOverwrittenWithRandomBytesJumpsAboveSevenAndAHalf` |
| Simulador dispara `HIGH` com múltiplos motivos | `RansomwareDetectorTest.simulatorPatternRaisesHighWithMultipleReasons` |
| Uso normal não dispara `HIGH` | `RansomwareDetectorTest.normalUseDoesNotAlert` |
| Rajada não perde eventos | `FolderWatcherTest.burstOfWritesIsNotLost` |
| Simulador não escreve fora do sandbox | invariantes + `guarded()` em `tools/RansomwareSimulator.java` |

---

## Limitações

- **É reativo.** Em espaço de usuário, o alerta sai durante ou depois do início do dano. É detecção precoce, não prevenção; bloquear exigiria um minifiltro de kernel, como fazem os EDRs.
- **Evasão por lentidão.** Um ataque que cifra um arquivo a cada 15 s nunca enche a janela de 10 s.
- **Falsos positivos.** Compactar ou copiar muitos arquivos de uma vez dispara S1. Só vira `HIGH` com um segundo sinal, mas uma whitelist ajudaria.
- **Eventos perdidos.** Sem hook de kernel, um `OVERFLOW` faz o diretório ser re-varrido; remoções perdidas só são reconciliadas no próximo start.
- **Renomear chega como `DELETED` + `CREATED`.** O arquivo renomeado não herda a entropia anterior, então o S2 depende de a sobrescrita ser vista antes da renomeação.

## Próximos passos

- Spring Web + SSE e um dashboard (React + Vite + TS).
- Consulta de reputação de hash (MalwareBazaar/VirusTotal).
- Resposta (quarentena) **somente com confirmação do usuário**. Fica como ideia, não está implementada.

---

## Estrutura do repositório

```
├── src/main/java/...      monitor (Spring Boot)
├── src/test/java/...      testes unitários
├── tools/                 RansomwareSimulator.java (benigno, fora do build)
├── sandbox/               única pasta observada (tem o marcador .filewatch-sandbox)
├── docs/index.html        site explicativo (GitHub Pages)
├── lab.cmd / lab.ps1      laboratório no Windows
├── lab.sh                 laboratório no Linux / macOS / Git Bash
└── SPEC-filewatch.md      especificação completa
```

## Uso responsável

O simulador existe para testar detecção, não para causar dano: ele só escreve em arquivos descartáveis que ele mesmo cria, numa pasta marcada. Não remova as proteções para apontá-lo para dados reais.

## Licença

[MIT](LICENSE) © 2026 Gabriel Moreno Serignolli
