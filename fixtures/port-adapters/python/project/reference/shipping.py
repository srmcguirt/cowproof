"""The Python reference: a tiny shipping calculator the port replaces."""

RATE_PER_KG = 0.5  # USD per kilogram
CURRENCY = "USD"


def quote(request):
    """The charge for one parcel, rounded to cents the way Python rounds."""
    kg = request["kg"]
    return {"kg": kg, "charge": round(kg * RATE_PER_KG, 2), "currency": CURRENCY}


def total(request):
    """The sum of the parcel charges: a plain float sum."""
    charges = request["charges"]
    return {"count": len(charges), "total": sum(charges)}
