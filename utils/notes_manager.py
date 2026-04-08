import json
import os

FILE_PATH = os.path.join("data", "analyst_notes.json")

def load_notes():
    if not os.path.exists(FILE_PATH):
        return {}

    with open(FILE_PATH, "r") as f:
        return json.load(f)

def save_notes(notes):
    with open(FILE_PATH, "w") as f:
        json.dump(notes, f, indent=4)

def add_note(ip, note):
    notes = load_notes()
    notes[ip] = note
    save_notes(notes)

def get_note(ip):
    notes = load_notes()
    return notes.get(ip, "")