from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static


class AdminTUI(App):
    TITLE = "CosmicSec Admin TUI"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("Welcome to CosmicSec interactive admin dashboard", id="body")
        yield Footer()


def main() -> None:
    AdminTUI().run()


if __name__ == "__main__":
    main()
