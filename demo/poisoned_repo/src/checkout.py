def calculate_total(items: list[dict[str, float]]) -> float:
    return sum(item["price"] for item in items)
