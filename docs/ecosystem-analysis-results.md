# Ecosystem Analysis: Complete Repository List

Full results from the MCP Security Linter ecosystem analysis described in our IWSPA 2026 paper.

## Scan Metadata

| Parameter | Value |
|-----------|-------|
| **Linter Version** | MCP Security Linter v1.4.2 |
| **Scan Date** | November 29, 2025 |
| **Repositories Analyzed** | 100 |
| **Repositories with Findings** | 5 (+ 1 false positive set) |
| **Total True Positive Findings** | 21 |
| **MCP-Aware Taint Tracking** | Enabled |

## Summary

| Category | Count |
|----------|-------|
| Shell | 31 |
| API | 24 |
| Database | 26 |
| File | 19 |
| **Total** | **100** |

## Vulnerable Repositories

| Repository | Category | Findings | Rules Triggered | Primary Issue |
|------------|----------|----------|-----------------|---------------|
| [dbx-mcp-server](https://github.com/amgadabdelhafez/dbx-mcp-server) | File | 9 | token-passthrough, unauthenticated-endpoint | Token storage paths leaked to logs |
| [image-worker-mcp](https://github.com/BoomLinkAi/image-worker-mcp) | File | 4 | command-exec, token-passthrough | Build script vulnerabilities |
| [mcp-abap-adt](https://github.com/fr0ster/mcp-abap-adt) | API | 4 | command-exec, command-exec-env | Environment pollution in dev scripts |
| [influxdb-mcp-server](https://github.com/idoru/influxdb-mcp-server) | Database | 3 | unauthenticated-endpoint | Missing authentication middleware |
| [CommandExecution](https://github.com/ryaker/CommandExecution) | Shell | 1 | command-exec | MCP tool arguments flow to shell execution |

## Complete Repository List

Each repository name links to its GitHub page. The **Commit SHA** column records the exact git revision at scan time (November 29, 2025), enabling full reproducibility.

| # | Repository | Category | Findings | Commit SHA |
|---|------------|----------|----------|------------|
| 1 | [CommandExecution](https://github.com/ryaker/CommandExecution) | Shell | 1 | `99ca594` |
| 2 | [Easy-Postgres-MCP](https://github.com/perrypixel/Easy-Postgres-MCP) | Database | 0 | `b0a279b` |
| 3 | [Figma-Context-MCP](https://github.com/GLips/Figma-Context-MCP) | API | 0 | `c11b1bc` |
| 4 | [Gmail-MCP-Server](https://github.com/GongRzhe/Gmail-MCP-Server) | API | 0 | `a890d19` |
| 5 | [MCP-Backup-Server](https://github.com/hexitex/MCP-Backup-Server) | File | 0 | `e4e8c5e` |
| 6 | [PowerShell-Exec-MCP-Server](https://github.com/DynamicEndpoints/PowerShell-Exec-MCP-Server) | Shell | 0 | `45b623d` |
| 7 | [REDIS-MCP-Server](https://github.com/GongRzhe/REDIS-MCP-Server) | Database | 0 | `9af5fa9` |
| 8 | [aws-s3-mcp](https://github.com/samuraikun/aws-s3-mcp) | File | 0 | `8e97db9` |
| 9 | [azure-devops-mcp](https://github.com/microsoft/azure-devops-mcp) | API | 0 | `d8b9642` |
| 10 | [bc-code-intelligence-mcp](https://github.com/JeremyVyska/bc-code-intelligence-mcp) | API | 0 | `d77cd97` |
| 11 | [cli-mcp-server](https://github.com/MladenSU/cli-mcp-server) | Shell | 0 | `5d30d70` |
| 12 | [cloudstorage-mcp](https://github.com/gitskyflux/cloudstorage-mcp) | File | 0 | `320d516` |
| 13 | [db-mcp-server](https://github.com/FreePeak/db-mcp-server) | Database | 0 | `88c8b41` |
| 14 | [dbx-mcp-server](https://github.com/amgadabdelhafez/dbx-mcp-server) | File | 9 | `27e6a91` |
| 15 | [docs-mcp-server](https://github.com/arabold/docs-mcp-server) | API | 0 | `39ee05a` |
| 16 | [duckdb_mcp](https://github.com/teaguesterling/duckdb_mcp) | Database | 0 | `17d83c3` |
| 17 | [exa-mcp-server](https://github.com/exa-labs/exa-mcp-server) | API | 0 | `1ec2078` |
| 18 | [fastmcp](https://github.com/punkpeye/fastmcp) | API | 0 | `118aa4c` |
| 19 | [file-system-mcp-server](https://github.com/calebmwelsh/file-system-mcp-server) | File | 0 | `767dca2` |
| 20 | [files-mcp](https://github.com/Files-com/files-mcp) | File | 0 | `4c82a65` |
| 21 | [files-mcp-server](https://github.com/microsoft/files-mcp-server) | File | 0 | `2a66a56` |
| 22 | [filesystem](https://github.com/dmatscheko/filesystem) | File | 0 | `c996517` |
| 23 | [filesystem-mcp](https://github.com/SylphxAI/filesystem-mcp) | File | 0 | `7e7449c` |
| 24 | [filesystem-mcp-server](https://github.com/cyanheads/filesystem-mcp-server) | File | 0 | `513ec49` |
| 25 | [firebase-mcp](https://github.com/gannonh/firebase-mcp) | Database | 0 | `4327231` |
| 26 | [gdrive-mcp-server](https://github.com/felores/gdrive-mcp-server) | File | 0 | `a1e0fa1` |
| 27 | [git-mcp](https://github.com/idosal/git-mcp) | Shell | 0 | `d1808ca` |
| 28 | [hdresearch-mcp-shell](https://github.com/hdresearch/mcp-shell) \u2020 | Shell | 0 | `f70bbcd` |
| 29 | [hyper-mcp-terminal](https://github.com/BigSweetPotatoStudio/hyper-mcp-terminal) | Shell | 0 | `e38caac` |
| 30 | [image-worker-mcp](https://github.com/BoomLinkAi/image-worker-mcp) | File | 4 | `029db7d` |
| 31 | [influxdb-mcp-server](https://github.com/idoru/influxdb-mcp-server) | Database | 3 | `2695298` |
| 32 | [influxdb3_mcp_server](https://github.com/influxdata/influxdb3_mcp_server) | Database | 0 | `ded93a1` |
| 33 | [magic-mcp](https://github.com/21st-dev/magic-mcp) | API | 0 | `ba1f71e` |
| 34 | [mako10k-mcp-shell-server](https://github.com/mako10k/mcp-shell-server) | Shell | 0 | `c6799c2` |
| 35 | [mcp-abap-adt](https://github.com/fr0ster/mcp-abap-adt) | API | 4 | `4f211ea` |
| 36 | [mcp-alchemy](https://github.com/runekaagaard/mcp-alchemy) | API | 0 | `f9d984e` |
| 37 | [mcp-bash](https://github.com/patrickomatik/mcp-bash) | Shell | 0 | `772010f` |
| 38 | [mcp-chrome](https://github.com/hangwin/mcp-chrome) | Shell | 12* | `e1301a0` |
| 39 | [mcp-cockroachdb](https://github.com/amineelkouhen/mcp-cockroachdb) | Database | 0 | `5c323e4` |
| 40 | [mcp-database](https://github.com/Melkeydev/mcp-database) | Database | 0 | `11003f5` |
| 41 | [mcp-database-server](https://github.com/executeautomation/mcp-database-server) | Database | 0 | `d6afa4b` |
| 42 | [mcp-db-manager](https://github.com/laduenasb/mcp-db-manager) | Database | 0 | `b23c93c` |
| 43 | [mcp-dbs](https://github.com/cuongtl1992/mcp-dbs) | Database | 0 | `5c949a2` |
| 44 | [mcp-filesystem](https://github.com/safurrier/mcp-filesystem) | File | 0 | `7a9d229` |
| 45 | [mcp-filesystem-server](https://github.com/bsmi021/mcp-filesystem-server) | File | 0 | `0ad99a7` |
| 46 | [mcp-gdrive](https://github.com/isaacphi/mcp-gdrive) | File | 0 | `5a94bdc` |
| 47 | [mcp-git](https://github.com/ukiuni/mcp-git) | Shell | 0 | `adae6c8` |
| 48 | [mcp-mongo-server](https://github.com/kiliczsh/mcp-mongo-server) | Database | 0 | `65f577b` |
| 49 | [mcp-official-servers](https://github.com/modelcontextprotocol/servers) | API | 0 | `d1d6a12` |
| 50 | [mcp-powershell-exec](https://github.com/dfinke/mcp-powershell-exec) | Shell | 0 | `52562b0` |
| 51 | [mcp-rest-api](https://github.com/dkmaker/mcp-rest-api) | API | 0 | `fb28239` |
| 52 | [mcp-sdlc-tracker](https://github.com/avinashsingh/mcp-sdlc-tracker) | API | 0 | `51975ec` |
| 53 | [mcp-server-airbnb](https://github.com/openbnb-org/mcp-server-airbnb) | API | 0 | `57d9d6c` |
| 54 | [mcp-server-bash](https://github.com/antonum/mcp-server-bash) | Shell | 0 | `356ce3d` |
| 55 | [mcp-server-bash-sdk](https://github.com/muthuishere/mcp-server-bash-sdk) | Shell | 0 | `4d267e9` |
| 56 | [mcp-server-browserbase](https://github.com/browserbase/mcp-server-browserbase) | Shell | 0 | `460a9c2` |
| 57 | [mcp-server-chart](https://github.com/antvis/mcp-server-chart) | API | 0 | `10330bc` |
| 58 | [mcp-server-chatsum](https://github.com/chatmcp/mcp-server-chatsum) | API | 0 | `5bf9298` |
| 59 | [mcp-server-cloudflare](https://github.com/cloudflare/mcp-server-cloudflare) | API | 0 | `0df3a67` |
| 60 | [mcp-server-code-execution-mode](https://github.com/elusznik/mcp-server-code-execution-mode) | Shell | 0 | `bd592eb` |
| 61 | [mcp-server-commands](https://github.com/g0t4/mcp-server-commands) | Shell | 0 | `76bf646` |
| 62 | [mcp-server-duckdb](https://github.com/ktanaka101/mcp-server-duckdb) | Database | 0 | `2cc7c29` |
| 63 | [mcp-server-kubernetes](https://github.com/Flux159/mcp-server-kubernetes) | Shell | 0 | `25c01dd` |
| 64 | [mcp-server-motherduck](https://github.com/motherduckdb/mcp-server-motherduck) | Database | 0 | `0794fe6` |
| 65 | [mcp-server-mysql](https://github.com/benborla/mcp-server-mysql) | Database | 0 | `6a03678` |
| 66 | [mcp-server-node](https://github.com/lucianoayres/mcp-server-node) | Shell | 0 | `fb46037` |
| 67 | [mcp-server-opendal](https://github.com/Xuanwo/mcp-server-opendal) | File | 0 | `f49ee92` |
| 68 | [mcp-server-shell](https://github.com/odysseus0/mcp-server-shell) | Shell | 0 | `2a17549` |
| 69 | [mcp-server-youtube-transcript](https://github.com/kimtaeyoon83/mcp-server-youtube-transcript) | API | 0 | `b8aa96f` |
| 70 | [mcp-shell](https://github.com/sonirico/mcp-shell) | Shell | 0 | `ecf792d` |
| 71 | [mcp-shell-server](https://github.com/tumf/mcp-shell-server) | Shell | 0 | `4da78d5` |
| 72 | [mcp-shell-server-1](https://github.com/smithery-ai/mcp-shell-server-1) | Shell | 0 | `58df6d3` |
| 73 | [mcp-sqlite](https://github.com/jparkerweb/mcp-sqlite) | Database | 0 | `1d6662d` |
| 74 | [mcp-terminal](https://github.com/GeLi2001/mcp-terminal) | Shell | 0 | `e46b81e` |
| 75 | [mcp-terminal-server](https://github.com/RichardTheuws/mcp-terminal-server) | Shell | 0 | `52325c4` |
| 76 | [mcp-webhook](https://github.com/kevinwatt/mcp-webhook) | API | 0 | `8c2f042` |
| 77 | [mcp_command_server](https://github.com/copyleftdev/mcp_command_server) | Shell | 0 | `8660406` |
| 78 | [mcp_server_filesystem](https://github.com/MarcusJellinghaus/mcp_server_filesystem) | File | 0 | `8c8993e` |
| 79 | [mkusaka-mcp-shell-server](https://github.com/mkusaka/mcp-shell-server) | Shell | 0 | `58df6d3` |
| 80 | [mongo-mcp](https://github.com/QuantGeekDev/mongo-mcp) | Database | 0 | `8bf1097` |
| 81 | [mongodb-mcp-server](https://github.com/mongodb-js/mongodb-mcp-server) | Database | 0 | `a585a82` |
| 82 | [mssql-mcp-onpremises](https://github.com/dnldelarosa/mssql-mcp-onpremises) | Database | 0 | `bd899aa` |
| 83 | [mssql_fastmcp_server](https://github.com/Nizarel/mssql_fastmcp_server) | Database | 0 | `ddb405a` |
| 84 | [mssql_mcp_server](https://github.com/RichardHan/mssql_mcp_server) | Database | 0 | `77b0c6a` |
| 85 | [n8n-mcp-server](https://github.com/leonardsellem/n8n-mcp-server) | API | 0 | `3b97d46` |
| 86 | [neo4j-mcp-official](https://github.com/neo4j/mcp) | Database | 0 | `3775609` |
| 87 | [notion-mcp-server](https://github.com/makenotion/notion-mcp-server) | API | 0 | `ffc1b18` |
| 88 | [playwright-mcp](https://github.com/microsoft/playwright-mcp) | Shell | 0 | `f4df37c` |
| 89 | [postgres-mcp](https://github.com/crystaldba/postgres-mcp) | Database | 0 | `18edf62` |
| 90 | [postgresql-mcp-server](https://github.com/HenkDz/postgresql-mcp-server) | Database | 0 | `cd6acba` |
| 91 | [powershell-mcp](https://github.com/gunjanjp/powershell-mcp) | Shell | 0 | `652f7fb` |
| 92 | [s3-mcp](https://github.com/rccyx/s3-mcp) | File | 0 | `bd194a9` |
| 93 | [s3-mcp-server](https://github.com/Geun-Oh/s3-mcp-server) | File | 0 | `74f85ca` |
| 94 | [shadcn-ui-mcp-server](https://github.com/Jpisnice/shadcn-ui-mcp-server) | API | 0 | `14bffe1` |
| 95 | [shell-mcp-server](https://github.com/blazickjp/shell-mcp-server) | Shell | 0 | `309537a` |
| 96 | [supabase-mcp](https://github.com/supabase-community/supabase-mcp) | Database | 0 | `48e3ed1` |
| 97 | [todoist-mcp-server](https://github.com/abhiz123/todoist-mcp-server) | API | 0 | `7080204` |
| 98 | [toolception](https://github.com/code-rabi/toolception) | Shell | 0 | `47c9258` |
| 99 | [vonage-mcp-server-api-bindings](https://github.com/Vonage-Community/vonage-mcp-server-api-bindings) | API | 0 | `29e1d9f` |
| 100 | [win-cli-mcp-server](https://github.com/simon-ami/win-cli-mcp-server) | Shell | 0 | `68cf341` |

### Notes

- **12\*** (`mcp-chrome`): All 12 findings are false positives from a bundled third-party library file (`ort.min.js`).
- **\u2020** (`hdresearch-mcp-shell`): Known false negative. TypeScript type annotations caused AST parsing failure, preventing analysis of command execution via `execa` with `shell:true`.

## Reproduction

To reproduce this analysis:

```bash
# Clone a repository at the exact analyzed revision
git clone --depth 1 <repo-url>
cd <repo-name>
git checkout <commit-sha>

# Run the linter with MCP-aware taint tracking
npx mcp-security-linter --format json /path/to/repo
```