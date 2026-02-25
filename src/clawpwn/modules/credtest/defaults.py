"""Default credentials database."""

from __future__ import annotations

# Common default credentials (username, password)
DEFAULT_CREDENTIALS: list[tuple[str, str]] = [
    ("root", ""),
    ("root", "root"),
    ("root", "password"),
    ("root", "toor"),
    ("admin", ""),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "12345"),
    ("administrator", "password"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
]

# Application-specific default credentials
APP_SPECIFIC_CREDENTIALS: dict[str, list[tuple[str, str]]] = {
    "phpmyadmin": [
        ("root", ""),
        ("root", "root"),
        ("pma", "pmapass"),
        ("phpmyadmin", "phpmyadmin"),
    ],
    "grafana": [
        ("admin", "admin"),
        ("admin", "password"),
    ],
    "jenkins": [
        ("admin", "admin"),
        ("admin", "password"),
        ("jenkins", "jenkins"),
    ],
    "tomcat": [
        ("admin", "admin"),
        ("tomcat", "tomcat"),
        ("admin", "s3cret"),
    ],
    "mysql": [
        ("root", ""),
        ("root", "root"),
        ("mysql", "mysql"),
    ],
    "postgres": [
        ("postgres", "postgres"),
        ("postgres", "password"),
    ],
}
