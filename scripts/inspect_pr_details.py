import json
import subprocess
import tempfile
import shutil
import os

candidates = [
    {
        "id": "utf8-api-35",
        "url": "https://github.com/TheKyleChau/utf8-api/pull/35",
        "repo": "https://github.com/TheKyleChau/utf8-api.git",
        "pkg": "fastapi",
        "old_ver": "0.141.1",
        "new_ver": "0.146.0",
        "base_sha": "5cc6686173ea64f0a1853c7074a7307bbc01285d",
        "head_sha": "d6953a5b4d36734e5861610f646ede0815f31b7e",
    },
    {
        "id": "am-webhook-88",
        "url": "https://github.com/alliedmodders/am-github-artifact-webhook/pull/88",
        "repo": "https://github.com/alliedmodders/am-github-artifact-webhook.git",
        "pkg": "fastapi",
        "old_ver": "0.159.1",
        "new_ver": "0.162.0",
        "base_sha": "70f5f98ffa5b100655c03924958613740dd205cf",
        "head_sha": "cce967b94feb6302eed551a60bede3a24192deab",
    },
    {
        "id": "duckbot-1538",
        "url": "https://github.com/duck-dynasty/duckbot/pull/1538",
        "repo": "https://github.com/duck-dynasty/duckbot.git",
        "pkg": "sqlalchemy",
        "old_ver": "2.1.1",
        "new_ver": "2.1.6",
        "base_sha": "1318eb7a90c6dad31af9c21cd9efd6009d6795d7",
        "head_sha": "a702d3adec658d59d3d2ef5cc234f343a82c11fe",
    },
    {
        "id": "synthetic-control-4",
        "url": "https://github.com/Maar10Herr/Synthetic-Control-Robustness-Envelopes-Public/pull/4",
        "repo": "https://github.com/Maar10Herr/Synthetic-Control-Robustness-Envelopes-Public.git",
        "pkg": "numpy",
        "old_ver": "2.5.2",
        "new_ver": "2.5.3",
        "base_sha": "938d255f3ba199f5f6b7170b0e039cd18484b7cd",
        "head_sha": "18fe812ca33f28b0f91d9640d2f347736d0567f0",
    },
    {
        "id": "credit-arena-11",
        "url": "https://github.com/shaikn6/credit-arena/pull/11",
        "repo": "https://github.com/shaikn6/credit-arena.git",
        "pkg": "pandas",
        "old_ver": "3.0.6",
        "new_ver": "3.1.0",
        "base_sha": "f9d0bddea4b3eadef41150edb3e76f25aa7d20d4",
        "head_sha": "375f87a7246ee48a5132c84bcc849be63bc248fe",
    },
    {
        "id": "homeward-61",
        "url": "https://github.com/sebiweise/homeward/pull/61",
        "repo": "https://github.com/sebiweise/homeward.git",
        "pkg": "cryptography",
        "old_ver": "48.0.1",
        "new_ver": "50.0.0",
        "base_sha": "8e272910bc593db1b07fcbb337fc20dae522e35c",
        "head_sha": "63432d88d4e6058111fde00a68cbf0ea3958e5d0",
    },
    {
        "id": "earthos-6",
        "url": "https://github.com/yajur408-lang/EarthOS/pull/6",
        "repo": "https://github.com/yajur408-lang/EarthOS.git",
        "pkg": "numpy",
        "old_ver": "2.4.6",
        "new_ver": "2.5.3",
        "base_sha": "33e28f99e81507e4505fa14ed3205fa6c01467d0",
        "head_sha": "5cad27fa867c0133786949b1a418d599a83d009f",
    }
]

print("Candidate list defined.")

