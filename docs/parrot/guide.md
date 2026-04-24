# Including a New Software Tool in Parrot OS

## A practical guide from initial proposal to long-term maintenance

Parrot OS is a Debian Stable-based distribution focused on security, privacy, forensics, and development. Getting a tool included is not just a matter of publishing source code. It is a packaging and maintenance commitment that must fit Parrot's Debian foundation, security posture, and community workflow.

## GitLab is the real entry point

Parrot's public contribution flow is centered on GitLab. For a new tool, the expected starting point is the community proposal workflow, not a direct packaging merge request without context.

The practical sequence is:

1. Propose the tool through Parrot's community workflow.
2. Explain clearly what the tool does and why it belongs in Parrot.
3. Prepare it as a Debian package.
4. Open a merge request only when the package is reviewable.
5. Stay available for review feedback and ongoing maintenance.

## Use the official proposal process

Parrot maintains a community repository for handling tool proposals:

- `parrotsec/project/community`

The current workflow is:

1. Open `Issues`.
2. Create a new issue.
3. Choose the `new_tool` template.
4. Complete all sections carefully.
5. Remain available for follow-up.

The `new_tool` template currently asks for:

- tool name
- purpose and functionality
- project website
- repository URL
- license
- programming language(s)
- dependencies
- installation method
- ecosystem fit
- benefit to Parrot users
- documentation or manual
- installation instructions
- maintainer contact information
- whether it was tested on Parrot

This is important because Parrot wants a technically reviewable proposal, not a vague feature request.

## What Parrot actually evaluates

Parrot's public guidance says a new tool should:

- serve a specific and well-defined purpose
- avoid structural changes to the operating system
- pass team review before integration

The public evaluation factors include:

- usefulness
- complexity
- security and stability
- maintainability
- compatibility with the existing ecosystem

A strong proposal answers these questions early:

- What exact problem does the tool solve?
- Why should Parrot ship it?
- Who will use it?
- How cleanly does it integrate with Debian packaging?
- Who will maintain it?

## Debian packaging is not optional

Parrot's docs explicitly say contributed tools should already be packaged according to Debian standards.

At minimum, that usually means a proper `debian/` directory containing core files such as:

- `debian/control`
- `debian/rules`
- `debian/changelog`

In real review practice, maintainers may also expect:

- copyright metadata
- manpages
- source format metadata
- test or autopkgtest metadata
- watch file
- build-system compatibility adjustments

The important distinction is this: a source repository is not enough. A submission should look like a Debian package.

## Build cleanly, not just locally

Parrot's development documentation references `sbuild` and `git-sbuildpkg`.

That signals a standard distro expectation: if your package only builds on your local workstation, it is not ready.

A serious submission should demonstrate:

- explicit build dependencies
- clean source package creation
- isolated builds
- no hidden dependence on local machine state

## Keep the package structurally quiet

Parrot explicitly says proposed tools should not introduce structural changes to the system.

In practice, that means avoiding:

- invasive system modifications
- always-on services unless clearly justified
- unusual install-time behavior
- packaging side effects outside normal Debian expectations

Parrot also documents a security-conscious platform model, including AppArmor support and restrictions around unnecessary privileged desktop usage. Your package should fit that ecosystem rather than fight it.

## Use the right communication channels

For practical contribution work, use:

- GitLab for issues and merge requests
- Forum for longer-lived discussion
- Telegram and Discord for community interaction
- `team@parrotsec.org` for formal contact

The important rule is simple: keep technical review where maintainers can track it, which usually means GitLab.

## Documentation reduces reviewer friction

A strong submission usually has:

- a clear README
- install and build instructions
- user-facing usage examples
- declared dependencies
- a clear maintainer
- a manpage or command help when appropriate

Good documentation does not guarantee acceptance, but poor documentation raises review cost and slows everything down.

## Acceptance begins maintenance

Inclusion in a distro is the start of responsibility, not the end.

Once accepted, the package needs someone to watch:

- upstream releases
- bug reports
- dependency changes
- packaging breakage
- compatibility with Parrot and Debian

A proposal is stronger when the maintainer makes that commitment explicit.

## Practical checklist

Before proposing a tool to Parrot, confirm:

1. The tool has a specific security, privacy, forensics, or development purpose.
2. It fits Parrot's audience.
3. It is open-source and packageable for Debian or Parrot.
4. It does not introduce structural OS changes.
5. It has a proper `debian/` packaging layout.
6. It builds cleanly in an isolated environment.
7. Dependencies are explicit.
8. Documentation is review-ready.
9. It has been tested on Parrot.
10. Someone is prepared to maintain it.

## The right mindset

The best submission strategy is not "how do I sell this tool." It is "how do I reduce reviewer risk."

That means:

- clear purpose
- minimal system impact
- Debian-quality packaging
- reproducible build behavior
- strong documentation
- realistic maintenance ownership

That is what makes a tool easier to accept.

## Sources

- Parrot community contributions: <https://parrotsec.org/docs/introduction/community-contributions/>
- Parrot development docs: <https://parrotsec.org/docs/development/>
- Parrot AppArmor docs: <https://parrotsec.org/docs/configuration/apparmor/>
- Parrot community repo: <https://gitlab.com/parrotsec/project/community>
- `new_tool` template: <https://gitlab.com/parrotsec/project/community/-/blob/main/.gitlab/issue_templates/new_tool.md>
