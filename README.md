# diskwhy

**Why is my disk filling up, and what is safe to remove?**

`diskwhy` (binary `dwhy`) is a Rust tool for Linux dev boxes and servers, used over ssh. It finds what is big *and what is growing*, explains each item, checks whether it is safe to delete, and removes it the way the owning tool would. It has a TUI for people and a JSON CLI (scan → plan → apply) that agents can drive within limits you set.

Status: pre-MVP, private. See [docs/DESIGN.md](docs/DESIGN.md) for scope and milestones.
