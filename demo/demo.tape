# ConsentML demo tape — regenerate the gif with:  vhs demo.tape
# Requires: vhs (brew install vhs) and consentml on PATH (pip install 'consentml').
# Run from this demo/ directory.

Output demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 760
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set PlaybackSpeed 1.0

# --- hidden setup: clean working dir with a tidy path and prompt ---
Hide
Type "SRC=$(pwd); rm -rf /tmp/consentml-demo && mkdir -p /tmp/consentml-demo" Enter
Type "cp $SRC/train.py /tmp/consentml-demo/ && cd /tmp/consentml-demo" Enter
Type 'export PS1="$ "' Enter
Type "clear" Enter
Show

# --- Beat 1: the code ---
Type "cat train.py" Sleep 500ms Enter
Sleep 4s
Type "clear" Enter

# --- Beat 2: record lineage ---
Type "python train.py" Sleep 500ms Enter
Sleep 2s

# --- Beat 3: tamper-evident ---
Type "consentml verify --db lineage.db" Sleep 500ms Enter
Sleep 3s

# --- Beat 4: the revocation (payoff) ---
Type "consentml revoke --subject-id alice@example.com --db lineage.db --dry-run" Sleep 500ms Enter
Sleep 4s

# --- Beat 5: file the dossier ---
Type "consentml export --subject-id alice@example.com --db lineage.db --out dossier.html" Sleep 500ms Enter
Sleep 3s

# --- closing ---
Type "# pip install consentml" Enter
Sleep 500ms
Type "# github.com/KaranamLokesh/consentml" Enter
Sleep 3s
