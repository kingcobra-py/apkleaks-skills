# Third-Party Notices

THE FOLLOWING SETS FORTH ATTRIBUTION NOTICES FOR THIRD-PARTY SOFTWARE AND DATA THAT MAY BE CONTAINED IN, BUNDLED WITH, OR DERIVED FROM PORTIONS OF THIS PRODUCT.

This product is a fork of and builds upon [APKLeaks](https://github.com/dwisiswant0/apkleaks). It decompiles APKs with [jadx](https://github.com/skylot/jadx), parses manifests with [pyaxmlparser](https://github.com/appknox/pyaxmlparser), and ships a detection ruleset (`config/regexes.json`) partly derived from the third-party regex collections noted below.

---

## Apache License 2.0

The following components are licensed under the Apache License, Version 2.0. The full license text is reproduced in [`LICENSE`](LICENSE).

- **APKLeaks**, Copyright © dwisiswant0 — the upstream project this fork is built on. https://github.com/dwisiswant0/apkleaks
- **jadx**, Copyright © Skylot — Dex to Java decompiler (auto-downloaded on first decompile). https://github.com/skylot/jadx
- **dex2jar**, Copyright © Bob Pan — DEX/Java conversion tooling. https://github.com/pxb1988/dex2jar
- **pyaxmlparser**, Copyright © Appknox — standalone Android manifest/AXML parser (runtime dependency). https://github.com/appknox/pyaxmlparser

---

## MIT License

The following components are licensed under the MIT License, reproduced below. Detection patterns in `config/regexes.json` for URLs, endpoints, and parameters are adapted from these projects.

- **LinkFinder**, Copyright © Gerben Javado — URL/endpoint discovery patterns. https://github.com/GerbenJavado/LinkFinder
- **gf**, Copyright © Tom Hudson (tomnomnom) — pattern set conventions. https://github.com/tomnomnom/gf

**License Text:**

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## GNU General Public License v3.0

The following component is licensed under the GNU General Public License v3.0. Some secret-detection regular expressions in `config/regexes.json` are adapted from it. The full license text is available at https://www.gnu.org/licenses/gpl-3.0.txt.

- **truffleHogRegexes**, Copyright © Dylan Ayrey (dxa4481) — credential/secret detection regexes. https://github.com/dxa4481/truffleHogRegexes

---

## Additional Acknowledgments

This project also benefits from the work of `apkurlgrep` ([@ndelphit](https://github.com/ndelphit)), the standalone APK parser by [@ph4r05](https://github.com/ph4r05), and the curated `NotKeyHacks` token set by [@dee__see](https://twitter.com/dee__see). See the README's Acknowledgments for the full list of contributors.
