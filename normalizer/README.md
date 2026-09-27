# Normalizer (v0.2.0) / Нормализатор (v0.2.0)

Converts Windows collector output (CSV) into a unified NDJSON event schema.
Standard library only, no external dependencies.

Превращает вывод Windows-коллектора (CSV) в единую схему событий NDJSON.
Только стандартная библиотека Python, внешних зависимостей нет.

## Usage / Запуск

```bash
python normalizer/normalize.py --input ./Triage_HOST_TS
python normalizer/normalize.py --input ./Triage_HOST_TS --output events.ndjson
