# Why I built mcpwn-red: Securing the AI Execution Layer

As LLMs become the "engine" behind modern security tools, we are introducing a new, unverified layer into our trusted environments. Tools like **MCPwn** represent a massive leap in AI-assisted pentesting, but they also introduce a critical question: **How do we know our AI engine hasn't been subverted?**

## The Risk of the "Hidden" Layer
In a traditional pentest, the operator knows exactly what a script does. In an AI-driven engagement, the LLM interprets a target's response and chooses a tool to call. This creates several "Shift-Left" security risks:
1.  **Instruction Smuggling:** Can a target "convince" the AI to run a command the operator didn't intend?
2.  **Poisoned Definitions:** Can a hostile target write a malicious tool definition into the AI's catalog?
3.  **Boundary Leakage:** Does the AI container isolate your host environment from the hostile code it's running?

## Enter mcpwn-red
I built `mcpwn-red` to serve as an **Adversarial Safety Harness**. It doesn't test the target; it tests the **executor**. 

By running automated probes against an MCPwn instance, `mcpwn-red` confirms that boundaries (Docker, Environment, and Protocol) are holding firm *before* you connect it to a real client network.

## Professional Validation
The tool is built on the official **Anthropic Model Context Protocol (MCP)** and has been engineered to meet the strict standards of the **Parrot OS** ecosystem. 

My goal with this project is to move the conversation from "AI can hack things" to "How do we make AI-assisted hacking safe for the operator?"

---
**Check out the project on GitHub:** [mcpwn-red](https://github.com/Mutasem-mk4/mcpwn-red)
**Install via PyPI:** `pip install mcpwn-red`
