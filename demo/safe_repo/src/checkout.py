def calculate_total(items: list[dict[str, float]]) -> float:
    return round(sum(item["price"] for item in items), 2)
