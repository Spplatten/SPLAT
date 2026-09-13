# Course preparation evidence

Prepared against revision **0027e577b75a118f8ec1ad29ddc5d567782ce9a7** on September 10, 2026. The initial working tree was clean. Production behavior was inspected for teaching assignments; production implementations were not changed.

## Executed gates

| Gate | Result | What it establishes |
| --- | --- | --- |
| Course runner, Lab/all | 29 checks passed | Representation/encoding and the decorator's fixture contracts |
| Selected repository regressions | 73 passed, 0 failed, 0 skipped | Eight selected suites on .NET 10/Windows |
| Course project build | 0 warnings, 0 errors | The lab and its Core reference compile for .NET 10 |
| Course link/fence gate | 128 local links passed; fences balanced | Linked course/source files exist and examples are closed |
| Course content and whitespace | 10 weekly files, 20 lessons; no trailing whitespace | Course structure and new-file hygiene |

The selected suites were AuditPayloadAndPreExecutionAuthTests, ArgumentVectorContractTests, WslLeasedExecutorWireTests, WorkspaceConfinementTests, SubstrateHealthHonestyTests, FailureIsNotEvidenceTests, ProjectExecutionEngineTests and DocumentationDriftTests.

The preparing host's selected SDK was 10.0.401 at C:\Users\s_pla\AppData\Local\Microsoft\dotnet\dotnet.exe. Its PATH-selected SDK was 9.0.317 under Program Files. This difference is why Run-Course.ps1 accepts an explicit SDK path and checks the selected version.

The initial repository-test record is C:\Users\s_pla\AppData\Local\Temp\SplatCourseBaseline\course-baseline.trx. It is local generated evidence, not a committed artifact. Rerunning the course regression command writes a fresh uniquely named temporary result directory.

The final runner regression also passed 73/73 after the lessons were written, with its record at C:\Users\s_pla\AppData\Local\Temp\SplatCourse-52c24bf0fa6b4819ba5f8fa2bc12b50e\course.trx. These are two runs of the same selected suites, not 146 distinct tests.

## Reproduce

~~~powershell
.\coursework\Run-Course.ps1 -Gate Lab
.\coursework\Run-Course.ps1 -Gate Regression
.\coursework\Run-Course.ps1 -Gate Links
~~~

Lab/all includes eight representation checks and twenty-one executor checks. The fixture never instantiates a native process launcher or a real leased executor. It covers pass-through of arguments/callbacks/tokens, unchanged results and exceptions, failure/timeout distinction, concurrent mission trace identity, metadata-only tags and operation without a listener.

The selected regression run compiles referenced .NET 10 projects. It is not a full solution/UI build. No claim is made that every existing test was run, that no host-specific test can have conditional behavior, or that the whole application is release-ready.

## Reviewed, not freshly executed

The Rust daemon, BPF source, supported-policy document and committed probe records were read. No root daemon was started, no kernel program was loaded, and no MCP-to-guest live run was performed for this course. GPU display, signed installation, model-provider traffic and enterprise deployment were not exercised.

Repair tickets R1–R5 are source observations with proposed new regressions; R6 is an advanced implementation assignment. Their production fixes remain student work. Older audit findings were used to locate regression themes and were rechecked against current code before inclusion.

Official Microsoft, SQLite, Rust and Linux references support the relevant lessons; repository behavior is grounded in the linked implementations and the executed gates above.
