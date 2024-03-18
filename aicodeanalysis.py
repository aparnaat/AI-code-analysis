import tkinter as tk
import re
import json

import re
from packaging import version

def scan(code, vuln, php_version):
    lst_patched = []
    lst_unpatched = []

    php_version = version.parse(php_version)

    for i in vuln:
        cveid = i["cveid"]
        year_str = cveid.split("-")[1]
        year = int(year_str) if year_str.isdigit() else 0
        threat = float(i["threat"])
        summary = i["summary"]
        fix_versions = i["fixVersions"]["base"]

        # Regular expression matching
        pattern = re.compile(fr'\b({"|".join(re.escape(word.lower()) for word in summary.split())})\b', re.IGNORECASE)
        matches = pattern.finditer(code)
        for j in matches:
            result = {
                "cveid": cveid,
                "threat": threat,
                "year": -year,
                "line": code.count('\n', 0, j.start()) + 1,
                "column": j.start() - code.rfind('\n', 0, j.start()),
                "match": j.group()
            }

            fix_versions = [version.parse(v) for v in fix_versions]
            if any(php_version >= v for v in fix_versions):
                lst_patched.append(result)
            else:
                lst_unpatched.append(result)

    # Sort the lists based on the reversed year in ascending order
    lst_patched = sorted(lst_patched, key=lambda x: x['year'])
    lst_unpatched = sorted(lst_unpatched, key=lambda x: x['year'])

    return lst_patched, lst_unpatched


def on_key_release(event):
    update_vulnerabilities()

def update_vulnerabilities():
    global code_entry, vuln_patched_listbox, vuln_unpatched_listbox, vuln, php_version_entry

    current_code = code_entry.get("1.0", tk.END)
    php_version = php_version_entry.get()
    lst_patched, lst_unpatched = scan(current_code, vuln, php_version)

    display_vulnerabilities(lst_patched, vuln_patched_listbox)
    display_vulnerabilities(lst_unpatched, vuln_unpatched_listbox)

def display_vulnerabilities(vulnerabilities, listbox):
    listbox.delete(0, tk.END)
    
    if vulnerabilities:
        for i in vulnerabilities:
            threat_color = get_color_from_threat(i['threat'])
            listbox.insert(tk.END, f"CVEID: {i['cveid']} - Threat Level: {i['threat']} - Line {i['line']}, Column {i['column']}: {i['match']}")
            listbox.itemconfig(tk.END, {'fg': threat_color})
    else:
        listbox.insert(tk.END, "No vulnerabilities found.")

def get_color_from_threat(threat):
    if threat < 2:
        return "light green"
    elif threat < 4:
        return "green"
    elif threat < 6:
        return "orange"
    else:
        return "red"

def start_operation():
    update_vulnerabilities()

with open("php_versions_vulnerabilities.json", "r") as json_file:
    vuln = json.load(json_file)["checks"]

root = tk.Tk()
root.title("Code Vulnerability Scanner")

# Code Entry
code_entry = tk.Text(root, wrap="word", width=70, height=30)
code_entry.bind("<KeyRelease>", on_key_release)
code_entry.grid(row=1, column=0, padx=10, pady=10)

# PHP Version Entry
php_version_label = tk.Label(root, text="Enter PHP Version:")
php_version_label.grid(row=0, column=0, padx=10, pady=5)
php_version_entry = tk.Entry(root)
php_version_entry.grid(row=0, column=1, padx=10, pady=5)

# Update Button
update_button = tk.Button(root, text="Update", command=start_operation)
update_button.grid(row=0, column=2, padx=10, pady=5)

# Patched Vulnerabilities Display
vuln_patched_listbox = tk.Listbox(root, width=70, height=30)
vuln_patched_listbox.grid(row=1, column=1, padx=10, pady=10)

# Unpatched Vulnerabilities Display
vuln_unpatched_listbox = tk.Listbox(root, width=70, height=30)
vuln_unpatched_listbox.grid(row=1, column=2, padx=10, pady=10)

root.mainloop()
