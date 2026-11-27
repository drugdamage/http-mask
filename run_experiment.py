"""Run unit tests and measure both CLI modes against hand-written references."""

from collections import Counter
from dataclasses import dataclass, field
from difflib import SequenceMatcher, unified_diff
import json
from pathlib import Path
import platform
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parent
MODES = {"remove": "Удаление заголовков", "mask": "Выборочное маскирование"}
LINE_ENDINGS = {"CRLF": "\r\n", "LF": "\n"}
TARGETS = {"authorization", "cookie", "set-cookie"}
RESULT = "результат"
REJECTED = "отказ"
Field = tuple[str, int]
Slot = tuple[str, int, int]
Element = tuple[str, int, str, int, str]


@dataclass
class Observation:
    start: str
    other_headers: list[str] = field(default_factory=list)
    values: dict[Slot, str] = field(default_factory=dict)
    elements: Counter[Element] = field(default_factory=Counter)


def normalize(text: str) -> str:
    return text.replace("\r\n", "\n")


def as_text(lines: list[str], eol: str) -> str:
    ending = LINE_ENDINGS[eol]
    return ending.join(lines) + ending


def attribute_elements(location: Field, attributes: list[str]) -> Counter[Element]:
    elements: Counter[Element] = Counter()
    occurrences: Counter[str] = Counter()
    for attribute in attributes:
        name, separator, value = attribute.strip(" \t").partition("=")
        name = name.rstrip(" \t").lower()
        occurrences[name] += 1
        label = name + separator + value.lstrip(" \t").lower()
        elements[(*location, "attribute", occurrences[name], label)] += 1
    return elements


def observe(text: str) -> Observation:
    """Extract values and diagnostic elements for measurement only."""
    start, *lines = normalize(text).split("\n")
    seen: Counter[str] = Counter()
    output = Observation(start)
    for line in lines:
        if not line:
            break
        name, separator, value = line.partition(":")
        header = name.lower()
        if not separator or header not in TARGETS:
            output.other_headers.append(line)
            continue

        seen[header] += 1
        location = (header, seen[header])
        if header == "authorization":
            words = value.strip(" \t").split(maxsplit=1)
            if words:
                output.elements[(*location, "scheme", 1, words[0])] += 1
            if len(words) == 2:
                output.values[(*location, 1)] = words[1]
            continue

        pairs = value.split(";")
        if header == "set-cookie":
            output.elements.update(attribute_elements(location, pairs[1:]))
            pairs = pairs[:1]
        for position, pair in enumerate(pairs, 1):
            name, separator, argument = pair.partition("=")
            if separator:
                output.elements[(*location, "cookie", position, name.strip(" \t"))] += 1
                output.values[(*location, position)] = argument.strip(" \t")
    return output


def get_marks(case: dict) -> tuple[dict[Slot, str], Counter[Element]]:
    secrets: dict[Slot, str] = {}
    elements: Counter[Element] = Counter()
    for annotation in case["annotations"]:
        location = (annotation["header"].lower(), annotation["occurrence"])
        for position, secret in annotation["secrets"]:
            slot = (*location, position)
            if not secret or slot in secrets:
                raise ValueError(f'{case["id"]}: invalid or repeated secret location')
            secrets[slot] = secret
        if "scheme" in annotation:
            elements[(*location, "scheme", 1, annotation["scheme"])] += 1
        for position, name in enumerate(annotation.get("cookie_names", []), 1):
            elements[(*location, "cookie", position, name)] += 1
        elements.update(attribute_elements(location, annotation.get("attributes", [])))
    return secrets, elements


def count_secrets(
    output: str,
    observed: Observation,
    reference: Observation,
    marked: dict[Slot, str],
) -> tuple[int, int]:
    """Count complete values in the full output and partial values in changed slots."""
    samples = Counter(marked.values())
    intact = {value: min(limit, output.count(value)) for value, limit in samples.items()}
    partial: Counter[str] = Counter()
    for slot, secret in marked.items():
        actual_value = observed.values.get(slot, "")
        intended_value = reference.values.get(slot, "")
        if not actual_value or actual_value == intended_value or secret in actual_value:
            continue

        # Compare only the material introduced by the mismatch in this value slot.
        changes = SequenceMatcher(None, intended_value, actual_value, autojunk=False)
        extra = [
            actual_value[start:end]
            for operation, _, _, start, end in changes.get_opcodes()
            if operation in {"replace", "insert"}
        ]
        if actual_value in secret or any(any(character in secret for character in span) for span in extra):
            partial[secret] += 1
    partial_count = sum(min(count, samples[value] - intact[value]) for value, count in partial.items())
    return sum(intact.values()), partial_count


def check_fixtures(data: dict) -> None:
    main = data["main"]
    additional = data["additional"]
    balance = Counter((case["group"], case["eol"]) for case in main)
    groups = {case["group"] for case in main}
    if len(main) != 24 or len(groups) != 6 or any(
        balance[group, eol] != 2 for group in groups for eol in LINE_ENDINGS
    ) or sum(case["group"] == "control" for case in main) != 4:
        raise ValueError("main series differs from the test plan")
    if len(additional) != 5 or len({case["id"] for case in main + additional}) != 29:
        raise ValueError("invalid number of additional cases or non-unique IDs")

    for case in main + additional:
        secrets, elements = get_marks(case)
        source = observe(as_text(case["input"], case["eol"]))
        source_values = {slot: value for slot, value in source.values.items() if value}
        if secrets != source_values or elements - source.elements:
            raise ValueError(f'{case["id"]}: annotations disagree with the input')
        if case in main:
            expected_mask = observe(as_text(case["expected"]["mask"], case["eol"]))
            if elements != expected_mask.elements:
                raise ValueError(f'{case["id"]}: annotations disagree with the masking reference')


def run_case(case: dict, series: str, group: str) -> dict:
    text = as_text(case["input"], case["eol"])
    source = observe(text)
    secrets, elements = get_marks(case)
    modes = {}
    for mode in MODES:
        reference_lines = case["expected"][mode]
        reference_text = as_text(reference_lines, case["eol"]) if reference_lines is not None else ""
        result = subprocess.run(
            [sys.executable, "-B", "mask_http.py", "--mode", mode],
            input=text.encode("utf-8"),
            capture_output=True,
            cwd=ROOT,
            timeout=10,
        )
        output, stderr = result.stdout.decode("utf-8"), result.stderr.decode("utf-8")
        normalized, expected_normalized = normalize(output), normalize(reference_text)
        observed = observe(normalized)
        full, partial = count_secrets(normalized, observed, observe(expected_normalized), secrets)
        if result.returncode == 0 and output:
            status = RESULT
        elif result.returncode != 0 and not output:
            status = REJECTED
        else:
            status = "ошибка"

        if reference_lines is not None:
            match = status == RESULT and normalized == expected_normalized and not stderr
        else:
            match = status == REJECTED and stderr.rstrip("\r\n") == case["expected_error"]
        modes[mode] = {
            "status": status,
            "return_code": result.returncode,
            "stdout": output,
            "stderr": stderr,
            "matches_reference": match,
            "expected_status": RESULT if reference_lines is not None else REJECTED,
            "expected_stdout": reference_text,
            "expected_stderr": case.get("expected_error", ""),
            "whole_secrets_remaining": full,
            "partial_secrets_remaining": partial,
            "secrets_remaining": full + partial,
            "diagnostic_elements_retained": sum((elements & observed.elements).values()),
            "start_line_preserved": observed.start == source.start if output else None,
            "other_headers_preserved": observed.other_headers == source.other_headers if output else None,
            "output_diff": "".join(
                unified_diff(
                    expected_normalized.splitlines(keepends=True),
                    normalized.splitlines(keepends=True),
                    fromfile="expected",
                    tofile="actual",
                )
            ),
        }
    return {
        "id": case["id"],
        "series": series,
        "group": case["group"],
        "group_name": group,
        "eol": case["eol"],
        "annotated_secrets": len(secrets),
        "annotated_diagnostic_elements": sum(elements.values()),
        "modes": modes,
    }


def percentage(numerator: int, denominator: int) -> float | None:
    return round(100 * numerator / denominator, 2) if denominator else None


def summarize(records: list[dict]) -> dict:
    main = [record for record in records if record["series"] == "main"]
    additional = [record for record in records if record["series"] == "additional"]
    common = [
        record for record in main
        if all(record["modes"][mode]["status"] == RESULT for mode in MODES)
    ]
    controls = [record for record in main if record["group"] == "control"]
    total_secrets = sum(record["annotated_secrets"] for record in common)
    total_elements = sum(record["annotated_diagnostic_elements"] for record in common)
    modes = {}
    for mode in MODES:
        remains = sum(record["modes"][mode]["secrets_remaining"] for record in common)
        retained = sum(record["modes"][mode]["diagnostic_elements_retained"] for record in common)
        modes[mode] = {
            "results": sum(record["modes"][mode]["status"] == RESULT for record in main),
            "secrets_remaining": remains,
            "secrets_remaining_percent": percentage(remains, total_secrets),
            "diagnostic_elements_retained": retained,
            "diagnostic_elements_retained_percent": percentage(retained, total_elements),
            "control_matches": sum(record["modes"][mode]["matches_reference"] for record in controls),
            "main_reference_matches": sum(record["modes"][mode]["matches_reference"] for record in main),
            "additional_reference_matches": sum(
                record["modes"][mode]["matches_reference"] for record in additional
            ),
        }
    return {
        "main_cases": len(main),
        "additional_cases": len(additional),
        "control_cases": len(controls),
        "common_main_cases": len(common),
        "common_annotated_secrets": total_secrets,
        "common_annotated_diagnostic_elements": total_elements,
        "modes": modes,
    }


def run_tests(results: Path) -> dict:
    arguments = ["-B", "-m", "unittest", "discover", "-s", "tests", "-v"]
    test = subprocess.run([sys.executable, *arguments], cwd=ROOT, capture_output=True, text=True)
    log = test.stdout + test.stderr
    (results / "unit_tests.txt").write_text(log, encoding="utf-8")
    count = re.search(r"^Ran (\d+) tests?\b", log, re.MULTILINE)
    return {
        "command": "python3 " + " ".join(arguments),
        "run": int(count[1]) if count else 0,
        "passed": len(re.findall(r" \.\.\. ok$", log, re.MULTILINE)),
        "return_code": test.returncode,
    }


TABLE_ROWS = {
    "results": "Фрагменты с результатом, шт.",
    "secrets_remaining": "Оставшиеся секреты, шт.",
    "secrets_remaining_percent": "Доля оставшихся секретов, %",
    "diagnostic_elements_retained": "Сохранённые элементы, шт.",
    "diagnostic_elements_retained_percent": "Доля сохранённых элементов, %",
    "control_matches": "Совпадения на контроле, шт.",
}


def format_number(number: int | float | None) -> str:
    return "н/п" if number is None else f"{number:g}".replace(".", ",")


def table_rows(summary: dict) -> list[list[str]]:
    return [
        [label, *(format_number(summary["modes"][mode][key]) for mode in MODES)]
        for key, label in TABLE_ROWS.items()
    ]


def flag(value: bool | None) -> str:
    if value is None:
        return "н/п"
    return "да" if value else "нет"


def outcome(mode: dict) -> str:
    if not mode["matches_reference"]:
        return f'{mode["status"]}, расхождение, код {mode["return_code"]}'
    if mode["status"] == REJECTED:
        return f'отказ, пустой stdout, код {mode["return_code"]}'
    return f'поле удалено, код {mode["return_code"]}'


def make_report(experiment: dict) -> str:
    summary, tests = experiment["summary"], experiment["unit_tests"]
    lines = [
        "# Отчёт об эксперименте",
        "",
        f'Среда выполнения — {experiment["python_implementation"]} {experiment["python_version"]}. '
        f'Пройдено {tests["passed"]} из {tests["run"]} модульных тестов.',
        "",
        "```bash",
        f'{tests["command"]}',
        "python3 -B run_experiment.py",
        "python3 -B mask_http.py --mode remove",
        "python3 -B mask_http.py --mode mask",
        "```",
        "",
        "Сценарий передаёт каждый размеченный фрагмент обоим вызовам CLI через stdin. "
        "Входы, разметка и отдельно записанные вручную эталоны находятся в `data/cases.json`. "
        "Каждый элемент массива строк завершается указанным в поле `eol` окончанием. "
        'Последний элемент `""` обозначает завершающую пустую строку, а `null` в эталоне обозначает отказ.',
        "",
        "Детали по каждому запуску, включая stdout, stderr, эталон и разницу с ним, "
        "записаны в `results/experiment.json`. Журнал тестов сохранён в `results/unit_tests.txt`.",
        "",
        "## Таблица 3. Показатели обработки основной серии",
        "",
        "| Показатель | Удаление заголовков | Выборочное маскирование |",
        "|---|---:|---:|",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in table_rows(summary))
    lines.extend([
        "",
        f'Основная серия включала {summary["main_cases"]} фрагментов, '
        f'дополнительная — {summary["additional_cases"]}. В общую выборку вошли фрагменты основной '
        f'серии с результатом в обоих режимах — {summary["common_main_cases"]} из {summary["main_cases"]}. '
        f'Знаменатель для доли оставшихся секретов равен {summary["common_annotated_secrets"]}, '
        f'для доли сохранённых диагностических элементов — {summary["common_annotated_diagnostic_elements"]}. '
        f'На контроле проверено {summary["control_cases"]} фрагмента.',
        "",
        "Вхождения заголовков нумеруются с 1 по каждому имени без учёта регистра, пары cookie "
        "нумеруются внутри соответствующего поля. Целые значения ищутся во всём выводе, "
        "а частичные — по совпадениям с исходным значением в изменённых участках соответствующего поля. "
        "Число совпадений ограничено числом размеченных вхождений каждого секрета. "
        "Схемы, имена cookie и атрибуты засчитываются в размеченных полях и вхождениях. "
        "Стартовая строка и список остальных заголовков сверяются отдельно после замены CRLF на LF. "
        "При пустой выдаче число выданных секретов и элементов равно нулю.",
        "",
        "## Дополнительные проверки",
        "",
        "| ID | Проверка | Ожидаемый исход в обоих режимах | Удаление заголовков | Выборочное маскирование |",
        "|---|---|---|---|---|",
    ])
    for record in experiment["cases"]:
        if record["series"] != "additional":
            continue
        modes = record["modes"]
        expected = (
            "Удаление поля, остальные строки сохранены"
            if modes["mask"]["expected_status"] == RESULT
            else "Отказ, ненулевой код, пустой stdout и краткое сообщение в stderr"
        )
        lines.append(
            f'| {record["id"]} | {record["group_name"]} | {expected} '
            f'| {outcome(modes["remove"])} | {outcome(modes["mask"])} |'
        )

    lines.extend([
        "",
        "## Результаты по фрагментам",
        "",
        "| ID | Группа | Окончание | Режим | Исход | Эталон | Секреты | Элементы | Старт | Прочие поля |",
        "|---|---|---|---|---|---|---:|---:|---|---|",
    ])
    for record in experiment["cases"]:
        for name, mode in record["modes"].items():
            lines.append(
                f'| {record["id"]} | {record["group_name"]} | {record["eol"]} | {name} '
                f'| {mode["status"]} | {flag(mode["matches_reference"])} | {mode["secrets_remaining"]} '
                f'| {mode["diagnostic_elements_retained"]} | {flag(mode["start_line_preserved"])} '
                f'| {flag(mode["other_headers_preserved"])} |'
            )
    return "\n".join(lines) + "\n"


def main() -> int:
    data = json.loads((ROOT / "data" / "cases.json").read_text(encoding="utf-8"))
    check_fixtures(data)
    results = ROOT / "results"
    results.mkdir(exist_ok=True)
    tests = run_tests(results)
    records = [
        run_case(case, series, data["groups"][case["group"]])
        for series in ("main", "additional")
        for case in data[series]
    ]
    experiment = {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "unit_tests": tests,
        "summary": summarize(records),
        "cases": records,
    }
    (results / "experiment.json").write_text(
        json.dumps(experiment, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (results / "experiment_report.md").write_text(make_report(experiment), encoding="utf-8")
    print("results/experiment_report.md")
    print("results/experiment.json")
    print("results/unit_tests.txt")
    all_cases_match = all(
        mode["matches_reference"]
        and mode["start_line_preserved"] is not False
        and mode["other_headers_preserved"] is not False
        for record in records
        for mode in record["modes"].values()
    )
    all_tests_pass = tests["return_code"] == 0 and tests["passed"] == tests["run"] > 0
    return 0 if all_tests_pass and all_cases_match else 1


if __name__ == "__main__":
    sys.exit(main())
