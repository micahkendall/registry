# Registry development

Keep the Plutarch datum layout, Python data generator, planners, and documented byte-level hash protocol in sync. Verify constructor/list encodings against Plutarch whenever a datum or redeemer type changes. When changing the content chain, update the tests and check that a 350 KiB entry still spans at least 30 sequential uploads. Do not describe the package as deployable until script export, transaction construction, and full-context policy checks have been verified.

Build and compile-check Plutarch terms with `cabal test all`; run `python3 -m unittest discover -s tests -v` for the content planner.
