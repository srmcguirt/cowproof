# cowproof

Run many AI builders in parallel on one project, each in its own copy-on-write clone, under a director that lets nothing land until it is proven.

- **COW**: every lane runs on a copy-on-write clone of your repository, inside an OS sandbox.
- **Proof**: every lane hands back a patch plus a proof capsule: checks re-run by a verifier the builder never controlled, which any machine can replay.
- **Cow-proof**: builders work in their own clones and cannot touch your real tree.

Status: design stage. Nothing here is ready to use yet. See [docs/design.md](docs/design.md).

## License

MIT. See [LICENSE](LICENSE).
