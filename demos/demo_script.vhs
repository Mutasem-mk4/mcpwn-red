# VHS tape for mcpwn-red demo
Output demos/mcpwn-red-demo.gif

Set Shell "bash"
Set FontSize 22
Set Width 1200
Set Height 800
Set Padding 40
Set Theme "Dracula"

# 1. Start with the banner
Type "mcpwn-red --help"
Sleep 500ms
Enter
Sleep 3s

# 2. Show the attack catalog
Type "mcpwn-red list"
Sleep 500ms
Enter
Sleep 4s

# 3. Simulate a probe
Type "mcpwn-red probe --transport stdio"
Sleep 500ms
Enter
Sleep 3s

# 4. Run the most "exciting" scan (Container Boundary)
Type "mcpwn-red scan --module container --transport stdio"
Sleep 500ms
Enter
Sleep 5s

# 5. Show the professional Report rendering
Type "mcpwn-red report --input mcpwn-red-results/results.json --format markdown"
Sleep 500ms
Enter
Sleep 5s
