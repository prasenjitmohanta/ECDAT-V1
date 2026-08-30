// ============================================================
//  main.cpp — Entry point of the ECDAT Qt Application
//
//  HOW QT APPS WORK (beginner):
//  ──────────────────────────────
//  1. Create a QApplication object (manages the event loop)
//  2. Create and show your main window
//  3. Call app.exec() — this starts the Qt event loop
//     (the loop waits for user clicks, key presses, etc.
//      and calls the right slots/handlers in response)
//  4. When the user closes the window, exec() returns 0
// ============================================================

#include <QApplication>
#include <QFont>
#include <QIcon>
#include "../include/MainWindow.h"

int main(int argc, char* argv[]) {
    // ── Step 1: Create the application ─────────────────────
    QApplication app(argc, argv);

    // Application metadata (shows in title bars, About dialogs)
    app.setApplicationName("ECDAT");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("SIH 2026 — NTRO");
    app.setWindowIcon(QIcon(":/icons/icon.png"));

    // Set a clean default font for the whole app
    QFont defaultFont("Segoe UI", 10);
    defaultFont.setHintingPreference(QFont::PreferFullHinting);
    app.setFont(defaultFont);

    // ── Step 2: Create and show the main window ─────────────
    MainWindow window;
    window.show();

    // ── Step 3: Start the Qt event loop ─────────────────────
    // This line BLOCKS until the user closes the application.
    return app.exec();
}
