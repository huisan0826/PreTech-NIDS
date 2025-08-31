from pathlib import Path
import csv
from openpyxl import Workbook


def csv_to_xlsx(csv_path: Path, xlsx_path: Path) -> None:
    wb = Workbook()
    ws = wb.active
    ws.title = "UseCases"

    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            ws.append(row)

    wb.save(xlsx_path)


def main():
    csv_path = Path("../docs/use_cases/UseCases.csv")
    xlsx_path = Path("../docs/use_cases/UseCases.xlsx")
    if not csv_path.exists():
        raise SystemExit("UseCases.csv not found. Please run export_use_cases_csv.py first.")
    csv_to_xlsx(csv_path, xlsx_path)
    print(f"Wrote {xlsx_path.resolve()}")


if __name__ == "__main__":
    main()



