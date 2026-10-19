# РБПО — исследование безопасности C++-приложения

Учебный консольный обработчик XML-записей на C++17. Программа получает XML из stdin или файла, выводит записи, подсчитывает их количество, сумму и среднее значение; по запросу сохраняет статистику в каталог reports/.

В рамках лабораторной работы исследованы две намеренно добавленные ошибки — CWE-120 (переполнение буфера) и CWE-22 (Path Traversal), — а также известные уязвимости сторонней библиотеки libxml2. Использованы SAST, SCA, AFL++ и AddressSanitizer.

Первоначальная версия намеренно уязвима и предназначена исключительно для локального учебного исследования.

## 1. Версии проекта

| Версия | Код приложения | libxml2 |
|---|---|---|
| vulnerable | Намеренные CWE-120 и CWE-22 | 2.11.5 |
| main | Исправлены CWE-120 и CWE-22 | 2.15.4 |

В main находится исправленный проект. Первоначальная версия сохранена отдельно в ZIP-архиве и при необходимости может быть размещена в ветке vulnerable.

Во время исследования также использовалась промежуточная сборка: libxml2 уже обновлена до 2.15.4, но ошибки собственного кода ещё не исправлены. Именно эта версия применялась для AFL++ и подтверждения переполнения через AddressSanitizer.

## 2. Требования и сборка на Ubuntu

Необходимы Ubuntu Linux, компилятор с поддержкой C++17, CMake 3.18+ и интернет для первоначальной загрузки libxml2.

Установка зависимостей:

```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config ca-certificates python3
```

Сборка исправленной версии:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j2
```

Проверка версии libxml2:

```bash
./build/rbpo_lab --version
```

Ожидаемая версия для main:

```text
libxml2 headers: 2.15.4
libxml2 runtime: 21504
```

Для сборки первоначальной уязвимой версии необходимо распаковать сохранённый архив в отдельную папку и выполнить те же команды CMake.

CMake автоматически загружает указанную в CMakeLists.txt версию libxml2, проверяет SHA-256 и собирает библиотеку статически. Устанавливать системную libxml2-dev не требуется.

## 3. Запуск приложения

Пример входного XML:

```xml
<records>
  <record name="Alice" value="10"/>
  <record name="Bob" value="20"/>
</records>
```

Чтение XML из stdin:

```bash
./build/rbpo_lab < corpus/input1.txt
```

Чтение из файла:

```bash
./build/rbpo_lab --input corpus/input2.txt
```

Сохранение статистики:

```bash
./build/rbpo_lab --input corpus/input1.txt --output result.txt
cat reports/result.txt
```

Ожидаемый вывод:

```text
Record: Alice = 10.00
Record: Bob = 20.00
Count: 2
Sum: 30.00
Average: 15.00
```

Файл отчёта создаётся внутри каталога reports/, расположенного относительно текущего рабочего каталога.

Программа принимает XML объёмом до 1 МиБ. Числовые значения должны быть конечными и находиться в диапазоне от -1e9 до 1e9.

## 4. Статический анализ (SAST)

Использовались три анализатора:

1. Cppcheck.
2. Clang-Tidy.
3. Clang Static Analyzer (scan-build).

Установка:

```bash
sudo apt install -y cppcheck clang clang-tools clang-tidy
mkdir -p analysis
```

### Cppcheck

```bash
cppcheck \
  --enable=all \
  --inconclusive \
  --check-level=exhaustive \
  --std=c++17 \
  --suppress=missingIncludeSystem \
  src/main.cpp \
  2> analysis/cppcheck-current.txt
```

### Clang-Tidy

```bash
clang-tidy -p build src/main.cpp \
  --checks='-*,clang-analyzer-*,bugprone-*,cert-*' \
  > analysis/clang-tidy-current.txt 2>&1
```

### Clang Static Analyzer

```bash
scan-build -o analysis/scan-build-current \
  cmake -S . -B build-scan-current \
  -DCMAKE_BUILD_TYPE=Debug
```

```bash
scan-build -o analysis/scan-build-current \
  cmake --build build-scan-current -j2 \
  2>&1 | tee analysis/scan-build-current.txt
```

Для проверки первоначальной версии команды запускаются в каталоге исходного уязвимого проекта.

Предупреждения в сторонней библиотеке libxml2 необходимо рассматривать отдельно от проблем собственного исходного кода.

## 5. Анализ зависимостей (SCA) и SBOM

Использовались:

- Syft — исследование состава компонентов и создание SBOM.
- Grype — анализ известных уязвимостей.
- Trivy — дополнительный SCA.
- CVE Binary Tool — дополнительный SCA.

При конфигурации CMake создаётся SBOM в формате CycloneDX 1.4:

```text
build/dependencies.cdx.json
```

Это декларативный SBOM прямой зависимости libxml2.

### Syft

```bash
syft dir:build -o cyclonedx-json=analysis/syft-current.cdx.json
```

### Grype

```bash
grype sbom:build/dependencies.cdx.json \
  2>&1 | tee analysis/grype-current.txt
```

Сохранение JSON-отчёта:

```bash
grype sbom:build/dependencies.cdx.json \
  -o json > analysis/grype-current.json
```

### Trivy

```bash
trivy sbom build/dependencies.cdx.json \
  > analysis/trivy-current.txt 2>&1
```

### CVE Binary Tool

```bash
printf 'vendor,product,version\nxmlsoft,libxml2,2.11.5\nxmlsoft,libxml2,2.15.4\n' \
  > analysis/components-both.csv
```

```bash
cve-bin-tool \
  --input-file analysis/components-both.csv \
  --nvd json-mirror \
  --disable-data-source OSV,GAD \
  --update now \
  2>&1 | tee analysis/cve-bin-tool-current.txt
```

В проведённом эксперименте Grype успешно сопоставил библиотеку с известными CVE.

Trivy не смог полноценно идентифицировать зависимость. CVE Binary Tool не смог загрузить базу NVD и использовал только 26 032 записи Red Hat. Поэтому результаты этих инструментов не подтверждают отсутствие уязвимостей.

### Сохранение SBOM до и после обновления

В исходной рабочей папке исследования:

```bash
mkdir -p analysis/sbom

cp build/dependencies.cdx.json \
  analysis/sbom/dependencies-before.cdx.json

cp build-fixed/dependencies.cdx.json \
  analysis/sbom/dependencies-after.cdx.json
```

Эти команды предполагают, что build был собран с libxml2 2.11.5, а build-fixed — с libxml2 2.15.4.

На новом клоне main обе версии SBOM автоматически не появятся: первоначальную нужно получить из исходной версии проекта.

## 6. AddressSanitizer

Сборка с ASan:

```bash
cmake -S . -B build-asan-current \
  -DCMAKE_BUILD_TYPE=Debug \
  -DENABLE_ASAN=ON

cmake --build build-asan-current -j2
```

Создание XML с длинным именем:

```bash
mkdir -p analysis

python3 - <<'PY'
from pathlib import Path

name = "A" * 80

Path("analysis/overflow.xml").write_text(
    f'<records><record name="{name}" value="10"/></records>\n'
)
PY
```

Запуск:

```bash
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  ./build-asan-current/rbpo_lab < analysis/overflow.xml
```

В первоначальной уязвимой версии AddressSanitizer обнаружил:

```text
ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 81
src/main.cpp:93:5
```

В исправленной версии тот же XML успешно обрабатывается.

Результат исходной проверки:

```text
analysis/asan-overflow.txt
```

## 7. Проверка Path Traversal

Проверка исправленной версии:

```bash
project_dir="$(pwd)"
test_dir="$(mktemp -d)"

mkdir -p "$test_dir/reports-demo"

(
  cd "$test_dir" || exit 1

  "$project_dir/build/rbpo_lab" \
    --input "$project_dir/corpus/input1.txt" \
    --output ../reports-demo/proof-fixed.txt

  if test -f reports-demo/proof-fixed.txt; then
    echo "FAIL: Path Traversal still works"
  else
    echo "PASS: File outside reports was not created"
  fi
)
```

До исправления приложение создавало файл вне разрешённого каталога reports/.

После исправления выводилось:

```text
Error: Path outside reports
PASS: File outside reports was not created
```

Лог исходной проверки:

```text
analysis/path-traversal.txt
```

## 8. Фаззинг AFL++

Установка:

```bash
sudo apt install -y afl++ clang llvm
```

Создание инструментированной сборки:

```bash
cmake -S . -B build-afl-current \
  -DCMAKE_C_COMPILER=afl-clang-fast \
  -DCMAKE_CXX_COMPILER=afl-clang-fast++ \
  -DCMAKE_BUILD_TYPE=Debug \
  -DENABLE_ASAN=ON

cmake --build build-afl-current -j2
```

Проверка инструментирования:

```bash
mkdir -p analysis

ASAN_OPTIONS=detect_leaks=0 \
  afl-showmap -o analysis/afl-coverage-current.txt \
  -- ./build-afl-current/rbpo_lab < corpus/input1.txt
```

Запуск фаззинга на 120 секунд:

```bash
AFL_SKIP_CPUFREQ=1 \
AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=0 \
afl-fuzz -i corpus -o findings -m none -t 2000 -V 120 \
  -- ./build-afl-current/rbpo_lab
```

AFL_SKIP_CPUFREQ пропускает проверку режима управления частотой процессора.

AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES позволяет продолжить тестирование при системной настройке core_pattern, но может снижать точность регистрации некоторых сбоев.

В рамках лабораторной фаззинг проводился на промежуточной версии: libxml2 2.15.4, но собственные уязвимости CWE-120 и CWE-22 ещё присутствовали.

Для повторения именно этого эксперимента необходимо использовать промежуточный исходный код, а не исправленный main.

Статистика фактического запуска:

```text
Время: 120 секунд
Количество запусков: 33000
Скорость: 274.97 запусков/с
Начальный корпус: 4 файла
Итоговый корпус: 307 файлов
Новые входы: 303
Стабильность: 100%
Заполненность карты AFL++: 2.73%
Сохранённые сбои: 0
Сохранённые зависания: 0
```

Заполненность карты AFL++ не является процентом покрытия исходного кода.

Лог:

```text
analysis/afl-fuzzer-stats.txt
```

## 9. Краткие результаты

| Проверка | До исправления | После исправления |
|---|---|---|
| Clang-Tidy | 3 предупреждения, включая strcpy() | 2 предупреждения |
| Cppcheck | Намеренные CWE не обнаружены | Новых предупреждений нет |
| Clang Static Analyzer | 48 предупреждений в libxml2 | 50 предупреждений в libxml2 |
| Grype | 28 совпадений с CVE | 2 совпадения с CVE |
| CWE-120 | Подтверждена ASan | Длинное имя обрабатывается |
| CWE-22 | Запись вне reports/ разрешена | Запись вне reports/ отклоняется |
| AFL++ | 33000 запусков, 0 сбоев | Повторная кампания не проводилась |

Предупреждения SAST и совпадения SCA не обязательно являются подтверждёнными эксплуатируемыми уязвимостями.

Исходная libxml2 2.11.5 затрагивалась CVE-2024-25062, однако условия эксплуатации этой CVE через интерфейс исследуемого приложения не были подтверждены.

## 10. Материалы проекта

```text
CMakeLists.txt              Конфигурация сборки и версия libxml2
src/main.cpp                Исходный код приложения
corpus/                     Начальный корпус AFL++
analysis/                   Отчёты инструментов и тестовые входы
analysis/sbom/              SBOM до и после обновления
README.md                   Инструкция сборки и анализа
dependencies.md             Описание зависимости
vulnerabilities.md          Описание исходных уязвимостей
```

Каталоги build*/, findings/ и большие временные отчёты scan-build не рекомендуется добавлять в Git.

Итоговый отчёт, полный первоначальный промпт и фактически использованная модель LLM предоставляются отдельно.
