# Third Party Notices

## IDA SDK

`thirdparty/ida-sdk/` holds one directory per vendored SDK, named after its `major.minor` line.
Each contains headers vendored verbatim from the Hex-Rays IDA SDK under `include/`, and a `VERSION`
file naming the exact release. These headers are the input to `S2GDU.Ida.Codegen`, which
generates the P/Invoke bindings in `S2GDU.Ida/Generated/`.

- [GitHub Repository](https://github.com/HexRaysSA/ida-sdk)
- **Vendored versions**:
  - `9.2` — [`9.2.0-sdk.1`](https://github.com/HexRaysSA/ida-sdk/tree/v9.2.0-sdk.1)
  - `9.4` — [`v9.4.0-release`](https://github.com/HexRaysSA/ida-sdk/tree/v9.4.0-release), commit `2348615c25f90e357cd2cc72fcfede1ba14ad41a`
  - `9.3` — [`9.3.0-sdk.3`](https://github.com/HexRaysSA/ida-sdk/tree/v9.3.0-sdk.3)

```
MIT License

Copyright (c) 2025 Hex-Rays SA

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

## IDA-GameDataTracker

The tracking engine (`S2GDU.Ida/Index`, `Rtti`, `Signatures`, `Crawler`, `Pathfinder` and the
import, backtrack and export flow) is a C# port of K4ryuu's IDA Pro plugin. The tuning constants
in `S2GDU.Ida/Config.cs` are carried over unchanged.

- [GitHub Repository](https://github.com/K4ryuu/IDA-GameDataTracker)

```
MIT License

Copyright (c) 2025 K4ryuu

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
