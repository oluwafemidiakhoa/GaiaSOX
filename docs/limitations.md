# Prototype boundaries

Synthetic population and approval flags are supplied by the caller; they are not independent source evidence. No real SQL collector, persistent key management, replay prevention, trusted timestamp, protected storage, or reviewer workflow exists yet. PASS means only that the synthetic rule passed. The demo uses an ephemeral key; it is not a durable offline verification package. Run locally with Python 3.11+, install requirements, then `python -m unittest discover -s tests -v` and `python gaiasox.py`. No CI is enabled to avoid unapproved resource usage.
