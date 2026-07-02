from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from advisory_miner.dockerize import detect, discover_candidates, has_docker_setup
from advisory_miner.dockerize.census import build_census
from advisory_miner.dockerize.generator import generate_files
from advisory_miner.dockerize.runner import dockerize_repo
from advisory_miner.dockerize.selector import build_repo_profile, select_web_app


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class DetectTests(unittest.TestCase):
    def test_detects_flask(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "requirements.txt", "flask==3.0.0\nrequests==2.31.0\n")
            write(root / "app.py", "from flask import Flask\napp = Flask(__name__)\n")
            kind = detect(root)
            self.assertIsNotNone(kind)
            assert kind is not None
            self.assertEqual(kind.language, "python")
            self.assertEqual(kind.framework, "flask")
            self.assertEqual(kind.entry_point, "app.py")
            self.assertEqual(kind.port, 8000)

    def test_detects_express(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root / "package.json",
                json.dumps(
                    {
                        "name": "demo",
                        "scripts": {"start": "node server.js"},
                        "dependencies": {"express": "^4.18.0"},
                    }
                ),
            )
            write(root / "server.js", "const express = require('express');\n")
            kind = detect(root)
            self.assertIsNotNone(kind)
            assert kind is not None
            self.assertEqual(kind.language, "node")
            self.assertEqual(kind.framework, "express")
            self.assertEqual(kind.entry_point, "server.js")

    def test_detects_go_net_http(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "go.mod", "module example.com/demo\ngo 1.22\n")
            write(
                root / "main.go",
                "package main\nimport \"net/http\"\nfunc main(){ http.ListenAndServe(\":8080\", nil) }\n",
            )
            kind = detect(root)
            self.assertIsNotNone(kind)
            assert kind is not None
            self.assertEqual(kind.language, "go")
            self.assertEqual(kind.port, 8080)

    def test_rejects_library_with_no_framework(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "requirements.txt", "numpy==1.26.0\n")
            write(root / "lib.py", "x = 1\n")
            self.assertIsNone(detect(root))

    def test_discovers_nested_backend_app(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "client" / "package.json", json.dumps({"scripts": {"dev": "vite"}, "dependencies": {"vite": "^6.0.0"}}))
            write(
                root / "backend" / "package.json",
                json.dumps(
                    {
                        "scripts": {"dev": "nodemon src/index.js"},
                        "dependencies": {"express": "^4.18.0"},
                    }
                ),
            )
            write(root / "backend" / "src" / "index.js", "const express = require('express');\n")
            kind = detect(root)
            self.assertIsNotNone(kind)
            assert kind is not None
            self.assertEqual(kind.root_path, "backend")
            self.assertEqual(kind.framework, "express")

    def test_llm_selector_can_choose_between_candidate_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "client" / "package.json", json.dumps({"scripts": {"dev": "vite"}, "dependencies": {"vite": "^6.0.0"}}))
            write(root / "backend" / "package.json", json.dumps({"dependencies": {"express": "^4.18.0"}}))
            write(root / "backend" / "src" / "index.js", "const express = require('express');\n")
            candidates = discover_candidates(root)
            self.assertEqual([item.root_path for item in candidates], ["backend", "client"])
            profile = build_repo_profile(root, candidates)
            self.assertEqual(profile.candidates[0]["root_path"], "backend")

            class SelectorClient:
                def json_response(self, system, user, max_output_tokens=1000):
                    self.user = user
                    return {"selected_root": "backend", "rationale": "API service", "confidence": "high"}

            client = SelectorClient()
            selected = select_web_app(client, root)
            self.assertIsNotNone(selected)
            assert selected is not None
            self.assertEqual(selected.root_path, "backend")
            self.assertEqual(client.user["candidates"][0]["root_path"], "backend")

    def test_llm_selector_falls_back_on_invalid_choice(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "backend" / "package.json", json.dumps({"dependencies": {"express": "^4.18.0"}}))
            write(root / "backend" / "src" / "index.js", "const express = require('express');\n")

            class BadSelectorClient:
                def json_response(self, system, user, max_output_tokens=1000):
                    return {"selected_root": "missing", "rationale": "bad", "confidence": "low"}

            selected = select_web_app(BadSelectorClient(), root)
            self.assertIsNotNone(selected)
            assert selected is not None
            self.assertEqual(selected.root_path, "backend")

    def test_has_docker_setup_finds_existing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "Dockerfile", "FROM python:3.12-slim\n")
            existing = has_docker_setup(root)
            self.assertIsNotNone(existing["dockerfile_path"])
            self.assertIsNone(existing["compose_path"])

    def test_census_reads_ci_and_run_hints(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / ".github" / "workflows" / "ci.yml", "run: npm test\n")
            write(root / "Procfile", "web: node src/index.js\n")
            write(root / "Makefile", "run:\n\tnpm start\n")
            write(root / "README.md", "# App\n\n## Running\n\nnpm start\n")
            census = build_census(root)
            self.assertIn(".github/workflows/ci.yml", census["ci_files"])
            self.assertIn("Procfile", census["deploy_files"])
            self.assertIn("run", census["makefile_targets"])
            self.assertIn("npm start", census["readme_run_excerpt"])


class RunnerTests(unittest.TestCase):
    def test_returns_not_attempted_when_not_a_web_app(self):
        with tempfile.TemporaryDirectory() as tmp:
            outcome = dockerize_repo(Path(tmp), client=None)
            self.assertFalse(outcome["attempted"])
            self.assertFalse(outcome["success"])

    def test_existing_dockerfile_validates_without_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "requirements.txt", "flask==3.0.0\n")
            write(root / "app.py", "from flask import Flask\napp = Flask(__name__)\n")
            write(root / "Dockerfile", "FROM python:3.12-slim\nCMD [\"python\", \"app.py\"]\n")
            outcome = dockerize_repo(root, client=None, skip_runtime=True)
            self.assertTrue(outcome["attempted"])
            self.assertEqual(outcome["mode"], "validate_existing")

    def test_generates_and_marks_success_when_skip_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "requirements.txt", "flask==3.0.0\n")
            write(root / "app.py", "from flask import Flask\napp = Flask(__name__)\n")

            class FakeClient:
                def __init__(self):
                    self.calls = 0

                def json_response(self, system, user, max_output_tokens=4000):
                    self.calls += 1
                    return {
                        "dockerfile": "FROM python:3.12-slim\nCOPY . /app\nWORKDIR /app\nRUN pip install -r requirements.txt\nEXPOSE 8000\nCMD [\"python\",\"app.py\"]\n",
                        "dockerignore": "__pycache__\n.git\n",
                        "compose_yml": "services:\n  app:\n    build: .\n    ports:\n      - \"8000:8000\"\n",
                    }

            fake = FakeClient()
            outcome = dockerize_repo(root, client=fake, skip_runtime=True)
            self.assertTrue(outcome["attempted"])
            self.assertEqual(outcome["mode"], "generated")
            self.assertIn("Dockerfile", outcome["files_written"])
            self.assertIn("compose.yml", outcome["files_written"])
            # Since skip_runtime, we couldn't truly verify; success is False but files are present.
            self.assertFalse(outcome["success"])
            self.assertEqual(fake.calls, 1)
            # Backup/restore returned the workspace to baseline (no Dockerfile remains).
            self.assertFalse((root / "Dockerfile").exists())

    def test_generates_inside_nested_app_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = root / "backend"
            write(
                backend / "package.json",
                json.dumps({"dependencies": {"express": "^4.18.0"}, "scripts": {"dev": "node src/index.js"}}),
            )
            write(backend / "src" / "index.js", "const express = require('express');\n")

            class FakeClient:
                def json_response(self, system, user, max_output_tokens=4000):
                    self.user = user
                    return {
                        "dockerfile": "FROM node:20-alpine\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci --omit=dev\nCOPY . .\nEXPOSE 3000\nCMD [\"node\",\"src/index.js\"]\n",
                        "dockerignore": "node_modules\n.git\n",
                        "compose_yml": "services:\n  app:\n    build: .\n    ports:\n      - \"3000:3000\"\n",
                    }

            fake = FakeClient()
            outcome = dockerize_repo(root, client=fake, skip_runtime=True)
            self.assertTrue(outcome["attempted"])
            self.assertEqual(outcome["kind"]["root_path"], "backend")
            self.assertEqual(fake.user["app_root"], ".")
            self.assertEqual(fake.user["selected_repo_root"], "backend")
            self.assertFalse((backend / "Dockerfile").exists())


class GeneratorTests(unittest.TestCase):
    def test_generate_files_parses_json_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "requirements.txt", "flask==3.0.0\n")
            write(root / "app.py", "from flask import Flask\napp = Flask(__name__)\n")
            kind = detect(root)
            self.assertIsNotNone(kind)
            assert kind is not None

            class FakeClient:
                def json_response(self, system, user, max_output_tokens=4000):
                    self.user = user
                    return {
                        "dockerfile": "FROM python:3.12-slim",
                        "dockerignore": "*.pyc",
                        "compose_yml": "services: {app: {build: .}}",
                    }

            df, di, cy = generate_files(FakeClient(), root, kind)
            self.assertIn("python", df)
            self.assertIn("pyc", di)
            self.assertIn("services", cy)

    def test_generate_files_raises_on_empty_dockerfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "requirements.txt", "flask==3.0.0\n")
            write(root / "app.py", "from flask import Flask\napp = Flask(__name__)\n")
            kind = detect(root)
            assert kind is not None

            class EmptyClient:
                def json_response(self, system, user, max_output_tokens=4000):
                    return {"dockerfile": "", "dockerignore": "", "compose_yml": ""}

            with self.assertRaises(ValueError):
                generate_files(EmptyClient(), root, kind)


if __name__ == "__main__":
    unittest.main()
