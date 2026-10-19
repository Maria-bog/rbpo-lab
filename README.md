# РБПО: первоначальная уязвимая версия

Небольшое консольное C++17-приложение читает XML-записи из stdin или файла,
печатает имена, количество, сумму и среднее. Сохранение включается только
аргументом `--output`; интерактивных вопросов нет. Один процесс обрабатывает
один документ и завершается. Собственный код содержит две намеренные ошибки:
переполнение стека и обход ограничения каталога отчётов. Они не исправлены.

## Формат

```xml
<records>
  <record name="Alice" value="10"/>
  <record name="Bob" value="20"/>
</records>
```

Имена — непустые UTF-8 строки; обычные безопасные примеры занимают не более
31 байта. Ограничение имени намеренно НЕ проверяется. Числа конечные,
от -1e9 до 1e9, десятичный разделитель — точка. Вход ограничен 1 MiB.
Пустой набор разрешён: среднее принято равным 0.00. Комментарии разрешены;
DTD и пространства имён не поддерживаются. Внешняя загрузка отключена.
Код выхода: 0 — успех, 1 — ошибка аргументов/формата/файла; переполнение
может аварийно завершить процесс. Суммирование использует double, поэтому
для дробей возможна обычная погрешность; вывод округлён до двух знаков.

## Сборка в Ubuntu

Команды выполняются из корня распакованного `rbpo-lab`.

```bash
sudo apt update
sudo apt install -y build-essential cmake ca-certificates python3
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j2
./build/rbpo_lab --version
./build/rbpo_lab < corpus/input1.txt
./build/rbpo_lab --input corpus/input2.txt
./build/rbpo_lab --input corpus/input1.txt --output result.txt
cat reports/result.txt
```

CMake >= 3.18. При первой конфигурации CMake скачивает исходники libxml2
2.11.5 и проверяет SHA-256. Системная libxml2 не используется; устанавливать
`libxml2-dev` не требуется. Библиотека собирается статически, поэтому при
запуске не нужна сеть или отдельная libxml2.so. Каталог reports создаётся
относительно текущего рабочего каталога, а не расположения бинарника.
Для переноса сборки без сети заранее сохраните архив и исходники зависимости;
`FETCHCONTENT_SOURCE_DIR_LIBXML2` можно направить на распакованную копию после
ручной проверки того же SHA-256. Эта настройка обходит автоматическую загрузку
и проверку хеша CMake, поэтому для основного эксперимента предпочтителен
обычный путь сборки выше.

Ожидаемый вывод input1.txt:

```text
Record: Alice = 10.00
Record: Bob = 20.00
Count: 2
Sum: 30.00
Average: 15.00
```

При сохранении дополнительно выводится `Saved: result.txt`. Файл содержит
только три строки Count/Sum/Average. Для остальных примеров:

| Файл | Count | Sum | Average |
|---|---:|---:|---:|
| input2.txt | 3 | 9.00 | 3.00 |
| input3.txt | 0 | 0.00 | 0.00 |
| input4.txt | 1 | 1.25 | 1.25 |

## AddressSanitizer и воспроизведение

```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON
cmake --build build-asan -j2
ASAN_OPTIONS=detect_leaks=0 ./build-asan/rbpo_lab < corpus/input1.txt
```

ASan применяется и к приложению, и к libxml2. `detect_leaks=0` отключает
только LeakSanitizer, а не проверки границ памяти. Это удобно в окружениях,
где LeakSanitizer не может читать /proc; на обычной Ubuntu можно его не задавать.
Безопасные локальные демонстрации обеих ошибок находятся в vulnerabilities.md.

## SAST

```bash
sudo apt install -y cppcheck clang clang-tools clang-tidy
mkdir -p analysis
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
python3 - <<'PY'
import json
from pathlib import Path
rows = json.loads(Path('build/compile_commands.json').read_text())
rows = [r for r in rows if Path(r['file']).name == 'main.cpp']
Path('analysis/compile_commands.json').write_text(json.dumps(rows, indent=2))
PY
cppcheck --project=analysis/compile_commands.json --enable=all \
  --inconclusive --std=c++17 2> analysis/cppcheck.txt
clang-tidy -p build src/main.cpp \
  --checks='clang-analyzer-*,bugprone-*,cert-*,security-*' \
  > analysis/clang-tidy.txt 2>&1
scan-build -o analysis/scan-build cmake -S . -B build-scan \
  -DCMAKE_BUILD_TYPE=Debug
scan-build -o analysis/scan-build cmake --build build-scan --clean-first -j2
```

Для scan-build используется отдельный каталог, чтобы действительно
перекомпилировать исходники под обёрткой анализатора. Его отчёт может содержать
и результаты по libxml2; в исследовании отделяйте их от src/main.cpp.
Для Cppcheck compilation database отфильтрована до собственного кода, без
подавления предупреждений. Пропуск ошибки не означает её отсутствия.
Предупреждение об опасном API также не равнозначно доказанному пути эксплуатации.

## AFL++

```bash
sudo apt install -y afl++ clang llvm
CC=afl-clang-fast CXX=afl-clang-fast++ \
  cmake -S . -B build-afl -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON
cmake --build build-afl -j2
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=0 \
  afl-fuzz -i corpus -o findings -m none -t 2000 -- ./build-afl/rbpo_lab
```

Здесь stdin используется автоматически: аргумент `@@` не нужен. Каталог
build-afl должен быть новым при смене компилятора. И C, и C++ компилируются
AFL-обёртками. Для ASan применяется `-m none`, поскольку он резервирует большое
виртуальное адресное пространство. Остановить фаззинг можно Ctrl+C.
В `corpus` четыре корректных файла, включая имя длиной 31 байт, непосредственно
перед границей переполнения. Вход, вызывающий падение, не включён в корпус.

Повторный запуск найденного crash:

```bash
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  ./build-asan/rbpo_lab < 'findings/default/crashes/ИМЯ_ФАЙЛА'
```

Подставьте реальное имя, не README. Путь зависит от версии/режима AFL++.
Фаззинг без `--output` исследует разбор входа и переполнение. CWE-22 проверяется
отдельным функциональным тестом: ASan не обнаруживает выход за каталог,
поскольку это логическая ошибка, а не нарушение границ памяти. Для покрытия
сохранения можно задать фиксированный `--output report.txt`, но это само по
себе не превращает CLI-путь в мутируемый stdin.

## SCA и зависимости

См. dependencies.md: версия и хеш, CVE, SBOM, Syft/Grype и Trivy, ограничения
обнаружения зависимостей C/C++. Syft создаёт SBOM; Grype и Trivy ищут уязвимости.

## Фактически выполненная проверка

В среде подготовки: GCC 13, CMake 3.31.6, Debug + ASan. Скачан официальный
архив libxml2; хеш совпал. Сборка выполнена с реальной зафиксированной
зависимостью. Все четыре примера завершились с кодом 0 и ожидаемой статистикой.
80 ASCII-символов в имени вызвали `AddressSanitizer: stack-buffer-overflow`,
запись 81 байта в `addRecord`, затем SIGABRT. Путь
`../reports-demo/proof.txt` создал файл вне reports внутри временного каталога.
Обычное сохранение и отклонение некорректного ввода также проверены.
SAST, SCA и длительный AFL++-запуск здесь не выполнялись: их результаты
предстоит получить в лабораторной, они не выдуманы.

## Соответствие требованиям

| Требование | Реализация / статус |
|---|---|
| Ubuntu, C++17, CMake | CMake >= 3.18; GCC/Clang; Linux filesystem |
| Небольшой основной код | 189 строк main.cpp |
| stdin и текстовый файл | XML через stdin или --input |
| Имена, значения, количество, сумма, среднее | process, addRecord, makeReport |
| Необязательное сохранение без диалога | --output, saveReport |
| Корректные обычные данные | Четыре примера успешно проверены |
| Реальное переполнение фиксированного буфера | char[32] + strcpy; ASan подтвердил |
| Реальный Path Traversal | Проверка строкового префикса; выход в reports-demo подтверждён |
| Разные типы, ровно две намеренные ошибки своего кода | CWE-120/787 и CWE-22 |
| Реально используемая сторонняя библиотека | xmlReadMemory, xmlGetProp, xmlFreeDoc и другие вызовы |
| Фиксированная версия с подтверждённой CVE | libxml2 2.11.5; CVE-2024-25062; ссылки в dependencies.md |
| Воспроизводимые исходники зависимости | Версия + SHA-256; без системной подмены |
| Проверка версии и возможность обновления | --version; изменение версии и хеша в CMake |
| SBOM и два SCA-сканера | Генерируемый CycloneDX; команды Syft, Grype, Trivy; обнаружение не гарантировано |
| Cppcheck, Clang SA, Clang-Tidy | Команды и compile_commands.json; запуск предстоит |
| AFL++, ASan | Обе AFL-обёртки; ASan на приложении и библиотеке |
| 3–5 корректных seeds | Четыре файла corpus |
| Один запуск — один вход | Нет цикла сервера/интерактивного диалога |
| Без сети при выполнении | Запрет внешней загрузки; HTTP/FTP отключены при сборке |
| Без системных команд | Нет system/exec/popen |
| Первоначальная уязвимая версия | Обе ошибки сохранены; исправлений нет |

Воспроизводимость здесь означает одинаковые исходники и конфигурацию
зависимости. Побайтовая идентичность бинарников при разных версиях компилятора,
CMake, libc и путях сборки не обещается. Зафиксируйте версии инструментов и дату
баз SCA в собственном отчёте.
