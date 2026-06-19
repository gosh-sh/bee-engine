# Bee-engine

Copyright (C) 2026 GOSH TECHNOLOGY LTD.

Bee-engine is free software: you can redistribute it and/or modify it under
the terms of the **GNU Affero General Public License**, version 3, as
published by the Free Software Foundation. The full license text is in
[LICENSE.md](LICENSE.md).

Bee-engine is distributed in the hope that it will be useful, but **WITHOUT
ANY WARRANTY**; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
for more details.

## Runtime dependency: Acki Nacki node

Bee-engine is a client SDK (mining, wallet management, proof generation and
verification, and cryptographic operations) for the **Acki Nacki** chain. It
does not run a chain itself — it signs and dispatches transactions to, and
reads contract and account state from, an Acki Nacki node.

The Acki Nacki node software is published by **GOSH TECHNOLOGY LTD.** under a
separate license — the **Acki Nacki Node License (ANNL)**, a Business Source
License with a two-year change date to GNU AGPL-3.0. The ANNL covers the node
software itself, not Bee-engine. Refer to the node repository for its current
license text and terms.

The AGPL terms of Bee-engine apply only to Bee-engine itself — the project's
own source code, builds, deployments, and modifications. They do not extend
to or override the licensing of any separately distributed software (such as
the Acki Nacki node) that Bee-engine interoperates with at runtime.
