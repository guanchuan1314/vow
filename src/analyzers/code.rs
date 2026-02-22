use std::path::Path;
use crate::{AnalysisResult, Issue, Severity, FileType};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct CustomAllowlist {
    pub python: Option<Vec<String>>,
    pub javascript: Option<Vec<String>>,
    pub java: Option<Vec<String>>,
    pub go: Option<Vec<String>>,
    pub ruby: Option<Vec<String>>,
    pub c: Option<Vec<String>>,
    pub cpp: Option<Vec<String>>,
    pub csharp: Option<Vec<String>>,
    pub php: Option<Vec<String>>,
    pub swift: Option<Vec<String>>,
    pub kotlin: Option<Vec<String>>,
    pub r: Option<Vec<String>>,
    pub mql5: Option<Vec<String>>,
    pub scala: Option<Vec<String>>,
    pub perl: Option<Vec<String>>,
    pub lua: Option<Vec<String>>,
    pub dart: Option<Vec<String>>,
    pub haskell: Option<Vec<String>>,
}

/// Top ~500 Python packages from PyPI + standard library
const KNOWN_PYTHON_PACKAGES: &[&str] = &[
    // Python standard library modules
    "os", "sys", "subprocess", "json", "urllib", "http", "re", "datetime", "collections", "itertools", 
    "functools", "operator", "pathlib", "typing", "asyncio", "threading", "multiprocessing", "queue",
    "time", "random", "math", "statistics", "decimal", "fractions", "csv", "xml", "html", "email",
    "base64", "hashlib", "hmac", "secrets", "ssl", "socket", "select", "signal", "logging", "unittest",
    "doctest", "argparse", "configparser", "shutil", "tempfile", "glob", "fnmatch", "pickle", "sqlite3",
    "gzip", "zipfile", "tarfile", "io", "struct", "copy", "pprint", "enum", "dataclasses", "contextlib",
    "inspect", "ast", "dis", "code", "importlib", "pkgutil", "modulefinder", "runpy", "types", "weakref",
    "gc", "site", "platform", "warnings", "traceback", "linecache", "keyword", "builtins", "__future__",
    "codecs", "encodings", "locale", "string", "textwrap", "unicodedata", "stringprep", "difflib",
    "heapq", "bisect", "array", "bytes", "memoryview", "bytearray", "mmap", "ctypes", "ctypes.util",
    // Popular PyPI packages from requirements
    "prisma", "pydantic", "fastapi", "uvicorn", "starlette", "httpx", "aiohttp", "celery", "redis", "pymongo",
    "sqlalchemy", "alembic", "pytest", "black", "ruff", "mypy", "poetry", "pdm", "hatch", "flit",
    "tox", "nox", "sphinx", "mkdocs", "typer", "rich", "textual", "polars", "dask", "ray", "prefect", 
    "airflow", "dagster", "mlflow", "wandb", "optuna", "lightgbm", "xgboost", "catboost", "transformers",
    "tokenizers", "datasets", "accelerate", "diffusers", "langchain", "llama_index", "openai", "anthropic",
    "cohere", "tiktoken", "chromadb", "pinecone", "weaviate", "qdrant", "milvus", "faiss", "annoy",
    "sentence_transformers", "spacy", "nltk", "gensim", "huggingface_hub", "gradio", "streamlit", "dash",
    "plotly", "bokeh", "altair", "seaborn", "pillow", "opencv", "imageio", "scikit_image", "torchvision",
    "torchaudio", "jax", "flax", "haiku", "einops", "sympy", "networkx", "igraph", "pyyaml", "toml",
    "tomli", "tomllib", "dotenv", "python_dotenv", "decouple", "dynaconf", "boto3", "botocore", "google_cloud",
    "azure", "paramiko", "fabric", "invoke", "click", "fire", "docopt", "argparse", "configparser",
    "dataclasses", "attrs", "pydantic_settings", "msgpack", "protobuf", "grpcio", "thrift", "avro",
    "arrow", "pyarrow", "orjson", "ujson", "rapidjson", "lxml", "beautifulsoup4", "bs4", "scrapy",
    "playwright", "selenium", "httptools", "uvloop", "gunicorn", "hypercorn", "daphne", "twisted",
    "gevent", "greenlet", "trio", "anyio", "structlog", "loguru", "sentry_sdk", "prometheus_client",
    "statsd", "psutil", "watchdog", "schedule", "apscheduler", "crontab", "pendulum", "arrow_dt",
    "dateutil", "pytz", "zoneinfo", "babel", "gettext", "passlib", "bcrypt", "cryptography", "pyjwt",
    "jwcrypto", "oauthlib", "authlib", "itsdangerous", "werkzeug", "jinja2", "mako", "chameleon",
    "django", "flask", "bottle", "falcon", "sanic", "tornado", "aiofiles", "motor", "beanie", "tortoise",
    "peewee", "pony", "mongoengine", "marshmallow", "cerberus", "voluptuous", "trafaret", "hypothesis",
    "faker", "factory_boy", "mimesis", "coverage", "tox", "nox",
    // More popular packages
    "requests", "urllib3", "setuptools", "certifi", "pip", "wheel", "six", "python-dateutil", "s3transfer", 
    "botocore", "jmespath", "pyasn1", "rsa", "boto3", "pyyaml", "awscli", "docutils", "colorama", "pyasn1-modules",
    "numpy", "charset-normalizer", "idna", "click", "blinker", "markupsafe", "jinja2", "flask", "werkzeug", "itsdangerous",
    "packaging", "pyparsing", "attrs", "jsonschema", "pyrsistent", "importlib-metadata", "zipp", "typing-extensions",
    "pillow", "cffi", "pycparser", "cryptography", "more-itertools", "pluggy", "py", "wcwidth", "packaging",
    "filelock", "distlib", "platformdirs", "virtualenv", "identify", "nodeenv", "pre-commit", "cfgv", "toml",
    "pytest", "iniconfig", "tomli", "exceptiongroup", "pytest-cov", "coverage", "tornado", "pyzmq", "jupyter-core",
    "traitlets", "jupyter-client", "python-json-logger", "platformdirs", "decorator", "ipython-genutils", "pickleshare",
    "backcall", "matplotlib-inline", "parso", "jedi", "stack-data", "asttokens", "executing", "pure-eval", "ipython",
    "comm", "debugpy", "psutil", "packaging", "nest-asyncio", "jupyter-server", "prometheus-client", "send2trash",
    "terminado", "tinycss2", "pandocfilters", "bleach", "defusedxml", "mistune", "nbformat", "fastjsonschema",
    "jupyter-server-terminals", "websocket-client", "jupyterlab-server", "babel", "json5", "jupyterlab",
    "notebook-shim", "nbconvert", "beautifulsoup4", "soupsieve", "lxml", "html5lib", "webencodings", "cssselect",
    "pyquery", "scrapy", "twisted", "zope-interface", "constantly", "incremental", "automat", "hyperlink",
    "service-identity", "pyopenssl", "queuelib", "w3lib", "parsel", "itemadapter", "itemloaders", "protego",
    "django", "sqlparse", "asgiref", "pytz", "djangorestframework", "markdown", "django-filter", "coreschema",
    "uritemplate", "coreapi", "openapi-codec", "simplejson", "ruamel-yaml", "ruamel-yaml-clib", "inflection",
    "drf-yasg", "uritemplate", "coreapi", "coreschema", "pytest-django", "factory-boy", "faker", "text-unidecode",
    "pandas", "pytz", "numpy", "python-dateutil", "six", "scipy", "matplotlib", "cycler", "kiwisolver", "fonttools",
    "pyparsing", "packaging", "pillow", "contourpy", "importlib-resources", "zipp", "seaborn", "statsmodels", "patsy",
    "scikit-learn", "joblib", "threadpoolctl", "networkx", "sympy", "mpmath", "nltk", "regex", "tqdm", "click",
    "openpyxl", "et-xmlfile", "xlsxwriter", "xlrd", "xlwt", "tabulate", "termcolor", "colorama", "rich", "pygments",
    "markdown-it-py", "mdurl", "textwrap3", "wcwidth", "prompt-toolkit", "pyperclip", "keyboard", "mouse", "pynput",
    "opencv-python", "opencv-contrib-python", "imageio", "imageio-ffmpeg", "moviepy", "proglog", "tqdm", "decorator",
    "requests-oauthlib", "oauthlib", "tweepy", "facebook-sdk", "google-api-python-client", "google-auth-httplib2",
    "google-auth-oauthlib", "google-auth", "cachetools", "pyasn1", "pyasn1-modules", "rsa", "httplib2", "uritemplate",
    "redis", "celery", "kombu", "billiard", "pytz", "click-didyoumean", "click-plugins", "click-repl", "vine",
    "amqp", "cached-property", "importlib-metadata", "zipp", "sqlalchemy", "greenlet", "psycopg2", "psycopg2-binary",
    "pymongo", "dnspython", "motor", "asyncio-mqtt", "paho-mqtt", "pyserial", "pyusb", "libusb1", "hidapi",
    "bleak", "pyble", "gattlib", "bluepy", "pexpect", "ptyprocess", "paramiko", "bcrypt", "pynacl", "sshtunnel",
    "fabric", "invoke", "pathlib2", "scandir", "pathspec", "watchdog", "argh", "pyyaml-include", "environs", "marshmallow",
    "webargs", "apispec", "apispec-webframeworks", "flasgger", "connexion", "clickclick", "inflection", "jsonschema",
    "fastapi", "starlette", "pydantic", "email-validator", "dnspython", "python-multipart", "aiofiles", "uvicorn",
    "gunicorn", "waitress", "gevent", "eventlet", "greenlet", "locust", "pyquery", "geventhttpclient", "websocket-client",
    // Additional packages for data science/ML
    "sklearn", "sk-learn", "tensorflow", "tf", "torch", "pytorch", "keras", "theano", "caffe", "mxnet",
    "cupy", "dask-ml", "joblib", "scikit-image", "skimage", "scikit-learn", "xarray", "h5py", "netcdf4", 
    "pyhdf", "tables", "pytables", "hdf5", "zarr", "parquet", "pyparquet", "feather", "pyarrow",
    // Web scraping & automation
    "requests-html", "pyppeteer", "splinter", "mechanize", "robobrowser", "grab", "webbot", "dryscrape",
    "ghost", "phantomjs", "chromedriver", "geckodriver", "webdriver-manager", "undetected-chromedriver",
    // Database connectors
    "cx-oracle", "oracledb", "pyodbc", "pymssql", "mysqlclient", "mysql-connector-python", "mariadb",
    "cassandra-driver", "neo4j", "py2neo", "rethinkdb", "couchdb", "elasticsearch", "elasticsearch-dsl",
    // GUI frameworks
    "tkinter", "tk", "pyqt5", "pyqt6", "pyside2", "pyside6", "wxpython", "kivy", "pyglet", "arcade",
    "pygame", "panda3d", "ursina", "moderngl", "vispy", "mayavi", "plotly-dash", "panel", "bokeh-server",
    // Image processing
    "pillow-simd", "wand", "pgmagick", "pymaging", "thumbor", "face_recognition", "opencv-contrib-python-headless",
    "opencv-python-headless", "mahotas", "scikit-image", "imageio-ffmpeg", "moviepy", "av", "ffmpeg-python",
    // API frameworks
    "fastapi-users", "fastapi-auth", "fastapi-pagination", "fastapi-cache", "slowapi", "limits", "flask-restful",
    "flask-restplus", "flask-api", "apiflask", "connexion", "falcon-cors", "hug", "eve", "sandman2",
    // Testing & mocking
    "pytest-xdist", "pytest-cov", "pytest-mock", "pytest-asyncio", "pytest-django", "pytest-flask",
    "nose", "nose2", "testtools", "testfixtures", "responses", "httmock", "requests-mock", "vcrpy",
    "betamax", "cassette", "mock", "unittest-mock", "flexmock", "doublex", "sure", "expects",
    // Async & concurrency
    "aioredis", "aiofiles", "aiopg", "aiomysql", "asyncpg", "databases", "encode-databases", "sqlalchemy-aio",
    "uvloop", "trio", "curio", "asks", "httpcore", "h11", "h2", "wsproto", "hypercorn", "daphne",
    // Configuration & environment
    "python-decouple", "environs", "dynaconf", "hydra-core", "omegaconf", "configargparse", "click-config-file",
    "pydantic-settings", "attrs", "cattrs", "desert", "marshmallow-dataclass", "dataclasses-json",
    // Logging & monitoring
    "loguru", "structlog", "python-json-logger", "colorlog", "sentry-sdk", "rollbar", "bugsnag", "airbrake",
    "newrelic", "elastic-apm", "opencensus", "opentelemetry", "jaeger-client", "ddtrace", "datadog",
    // Serialization
    "msgpack", "cbor", "cbor2", "bson", "pycbor", "flatbuffers", "capnproto", "thrift", "avro-python3",
    "fastavro", "snappy", "lz4", "zstd", "brotli", "lzma", "gzip", "zlib", "blosc",
    // Cloud & deployment
    "awscli", "aws-sam-cli", "chalice", "zappa", "serverless", "pulumi", "troposphere", "cloudformation-cli",
    "docker", "docker-compose", "kubernetes", "kubectl", "helm", "terraform", "ansible", "fabric3",
    // File processing
    "openpyxl", "xlsxwriter", "xlrd", "xlwt", "xlutils", "pyexcel", "tablib", "csvkit", "petl",
    "records", "dataset", "csvvalidator", "pandas-profiling", "sweetviz", "pandas-bokeh", "cufflinks",
];

/// Top ~500 JavaScript/Node.js packages from npm + Node.js built-ins
const KNOWN_JS_PACKAGES: &[&str] = &[
    // Node.js built-in modules
    "fs", "path", "os", "crypto", "http", "https", "url", "querystring", "util", "events", "stream",
    "buffer", "child_process", "cluster", "dgram", "dns", "domain", "net", "readline", "repl", "tls",
    "tty", "vm", "zlib", "assert", "process", "console", "timers", "module", "worker_threads", "perf_hooks",
    "async_hooks", "inspector", "trace_events", "v8", "string_decoder", "punycode", "constants",
    // Required packages from specification  
    "zod", "@prisma/client", "prisma", "@trpc/server", "@trpc/client", "drizzle-orm", "kysely", "knex", 
    "sequelize", "typeorm", "mongoose", "@supabase/supabase-js", "firebase", "@firebase/app", "next", 
    "nuxt", "svelte", "@sveltejs/kit", "solid-js", "qwik", "astro", "remix", "gatsby", "vite", "esbuild", 
    "rollup", "parcel", "turbopack", "tsup", "unbuild", "vitest", "jest", "mocha", "chai", "playwright", 
    "puppeteer", "cypress", "@testing-library/react", "@testing-library/jest-dom", "msw", "supertest", 
    "nock", "sinon", "tailwindcss", "@tailwindcss/typography", "postcss", "autoprefixer", "sass", "less", 
    "styled-components", "@emotion/react", "@emotion/styled", "@mui/material", "@chakra-ui/react", 
    "@mantine/core", "@radix-ui/react-dialog", "@headlessui/react", "shadcn", "lucide-react", 
    "@heroicons/react", "framer-motion", "gsap", "three", "@react-three/fiber", "d3", "chart.js", 
    "recharts", "@nivo/core", "echarts", "mapbox-gl", "leaflet", "zustand", "jotai", "recoil", 
    "@reduxjs/toolkit", "mobx", "valtio", "pinia", "vuex", "@tanstack/react-query", "swr", "apollo-client", 
    "@apollo/client", "urql", "graphql", "graphql-tag", "trpc", "tRPC", "@hono/node-server", "hono", 
    "fastify", "koa", "nest", "@nestjs/core", "@nestjs/common", "express", "cors", "helmet", "compression", 
    "morgan", "winston", "pino", "bunyan", "loglevel", "debug", "dotenv", "cross-env", "env-cmd", "zx", 
    "execa", "shelljs", "commander", "yargs", "inquirer", "prompts", "ora", "chalk", "picocolors", "clsx", 
    "classnames", "date-fns", "dayjs", "luxon", "moment", "uuid", "nanoid", "cuid", "ulid", "bcrypt", 
    "bcryptjs", "argon2", "jsonwebtoken", "jose", "passport", "next-auth", "@auth/core", "lucia", "oslo", 
    "arctic", "@clerk/nextjs", "sharp", "jimp", "canvas", "pdf-lib", "pdfkit", "xlsx", "csv-parse", 
    "papaparse", "cheerio", "jsdom", "linkedom", "turndown", "marked", "remark", "rehype", "unified", 
    "mdx", "@mdx-js/react", "contentlayer", "sanity", "strapi", "payload", "directus", "keystone", 
    "medusa", "@shopify/hydrogen", "stripe", "@stripe/stripe-js", "paypal", "lemon-squeezy", "resend", 
    "nodemailer", "@sendgrid/mail", "twilio", "@aws-sdk/client-s3", "@aws-sdk/client-ses", 
    "@google-cloud/storage", "@azure/storage-blob", "ioredis", "bullmq", "amqplib", "kafkajs", "socket.io", 
    "ws", "@trpc/server", "superjson", "devalue", "ky", "got", "undici", "ofetch", "@upstash/redis", 
    "@upstash/ratelimit", "@vercel/analytics", "@vercel/og", "@sentry/nextjs", "@sentry/node", "openai", 
    "@anthropic-ai/sdk", "langchain", "llamaindex", "ai", "@ai-sdk/openai", "chromadb", "pinecone", 
    "weaviate-ts-client",
    // Popular npm packages
    "lodash", "chalk", "request", "commander", "express", "debug", "ms", "mkdirp", "colors", "async", "underscore",
    "moment", "bluebird", "q", "uuid", "semver", "yargs", "glob", "minimatch", "inherits", "util-deprecate", "safe-buffer",
    "react", "react-dom", "prop-types", "classnames", "react-router", "react-router-dom", "history", "hoist-non-react-statics",
    "redux", "react-redux", "redux-thunk", "reselect", "immutable", "axios", "isomorphic-fetch", "whatwg-fetch", "node-fetch",
    "jquery", "bootstrap", "popper.js", "@popperjs/core", "moment-timezone", "date-fns", "dayjs", "luxon", "numbro", "numeral",
    "vue", "@vue/cli-service", "vuex", "vue-router", "vuetify", "vue-loader", "vue-template-compiler", "vue-style-loader",
    "angular", "@angular/core", "@angular/common", "@angular/platform-browser", "@angular/router", "@angular/forms",
    "@angular/http", "@angular/animations", "rxjs", "tslib", "zone.js", "@angular/cli", "@angular/compiler-cli",
    "webpack", "webpack-cli", "webpack-dev-server", "html-webpack-plugin", "mini-css-extract-plugin", "css-loader",
    "style-loader", "file-loader", "url-loader", "babel-loader", "ts-loader", "source-map-loader", "terser-webpack-plugin",
    "@babel/core", "@babel/preset-env", "@babel/preset-react", "@babel/preset-typescript", "@babel/plugin-proposal-class-properties",
    "babel-polyfill", "@babel/polyfill", "core-js", "regenerator-runtime", "@babel/runtime", "@babel/helpers",
    "typescript", "ts-node", "@types/node", "@types/react", "@types/react-dom", "@types/jest", "@types/lodash",
    "eslint", "prettier", "husky", "lint-staged", "@typescript-eslint/parser", "@typescript-eslint/eslint-plugin",
    "eslint-config-prettier", "eslint-plugin-prettier", "eslint-plugin-react", "eslint-plugin-react-hooks",
    "jest", "@testing-library/react", "@testing-library/jest-dom", "@testing-library/user-event", "enzyme", "sinon",
    "mocha", "chai", "supertest", "nyc", "karma", "jasmine", "protractor", "puppeteer", "playwright", "cypress",
    "nodemon", "concurrently", "cross-env", "dotenv", "config", "yargs-parser", "minimist", "optimist", "nopt",
    "express-session", "connect-redis", "passport", "passport-local", "passport-jwt", "jsonwebtoken", "bcryptjs", "bcrypt",
    "mongoose", "sequelize", "typeorm", "prisma", "knex", "bookshelf", "objection", "pg", "mysql2", "sqlite3", "redis",
    "socket.io", "ws", "uws", "sockjs", "engine.io", "primus", "faye-websocket", "websocket", "ws", "isomorphic-ws",
    "nodemailer", "sendgrid", "mailgun-js", "@sendgrid/mail", "emailjs", "mandrill-api", "sparkpost", "ses", "postmark",
    "multer", "formidable", "busboy", "multiparty", "connect-multiparty", "express-fileupload", "gridfs-stream", "multer-gridfs-storage",
    "cors", "helmet", "morgan", "compression", "serve-static", "cookie-parser", "express-validator", "joi", "yup", "ajv",
    "winston", "bunyan", "pino", "log4js", "npmlog", "debug", "signale", "consola", "kleur", "colorette", "ansi-colors",
    "fs-extra", "graceful-fs", "rimraf", "del", "make-dir", "move-file", "copy-file", "cpy", "globby", "fast-glob",
    "chokidar", "gaze", "node-watch", "sane", "watchpack", "webpack-dev-middleware", "webpack-hot-middleware", "react-hot-loader",
    "pm2", "forever", "supervisor", "node-dev", "nodemon", "reload", "livereload", "browser-sync", "lite-server", "serve",
    "http-server", "json-server", "mock-json-server", "nock", "superagent", "got", "bent", "needle", "phin", "cross-fetch",
    // Additional React ecosystem
    "create-react-app", "react-scripts", "react-app-rewired", "customize-cra", "craco", "@craco/craco", "react-helmet",
    "react-helmet-async", "react-loadable", "loadable-components", "@loadable/component", "react-window", "react-virtualized",
    "react-select", "react-datepicker", "react-hook-form", "formik", "react-final-form", "react-use", "react-query",
    "react-router-config", "connected-react-router", "react-transition-group", "react-spring", "react-pose", "lottie-react",
    // Vue ecosystem  
    "@vue/composition-api", "vue-property-decorator", "vue-class-component", "vue-meta", "vue-i18n", "vue-apollo",
    "vue-lazyload", "vue-virtual-scroller", "vue-observe-visibility", "vue-infinite-loading", "vue-moment",
    // Angular ecosystem
    "@angular/material", "@angular/cdk", "@angular/flex-layout", "@angular/service-worker", "@angular/pwa",
    "ng-bootstrap", "ngx-bootstrap", "prime-ng", "clarity-angular", "ng-zorro-antd", "ngx-toastr", "ngx-spinner",
    // Build tools & bundlers
    "rollup-plugin-node-resolve", "rollup-plugin-commonjs", "rollup-plugin-babel", "rollup-plugin-terser",
    "parcel-bundler", "@parcel/transformer-sass", "@parcel/transformer-typescript", "snowpack", "wmr", "vitejs",
    // Testing utilities
    "ava", "tap", "tape", "@storybook/react", "@storybook/addon-essentials", "chromatic", "percy", "backstopjs",
    "jest-environment-jsdom", "babel-jest", "ts-jest", "@types/jest", "jest-extended", "jest-date-mock",
    // Database & ORM
    "pg-pool", "pg-cursor", "mysql", "mariadb", "better-sqlite3", "node-sqlite3", "level", "leveldb", "nedb",
    "tingodb", "lokijs", "lowdb", "node-json-db", "flat-file-db", "diskdb", "jsonfile", "fs-jetpack",
    // HTTP clients & servers
    "koa-router", "koa-bodyparser", "koa-cors", "koa-helmet", "koa-session", "koa-static", "koa-mount",
    "fastify-cors", "fastify-helmet", "fastify-jwt", "fastify-cookie", "fastify-multipart", "fastify-static",
    "hapi", "@hapi/hapi", "@hapi/joi", "@hapi/boom", "@hapi/inert", "@hapi/vision", "restify", "micro",
    // WebSocket & real-time
    "socket.io-client", "sockjs-client", "ws", "uws", "faye", "pusher", "pusher-js", "ably", "firebase-admin",
    // Authentication & security
    "passport-google-oauth20", "passport-facebook", "passport-twitter", "passport-github2", "passport-oauth2",
    "oauth", "oauth2", "node-oauth2-server", "express-oauth-server", "jsonwebtoken", "node-jsonwebtoken",
    "crypto-js", "bcryptjs", "argon2", "speakeasy", "otplib", "qrcode", "helmet", "csurf", "express-rate-limit",
    // Utility libraries
    "ramda", "immutable", "immer", "mori", "seamless-immutable", "highland", "most", "xstream", "bacon",
    "kefir", "flyd", "callbag", "rxjs-compat", "zen-observable", "symbol-observable", "core-js-pure",
    "tslib", "utility-types", "type-fest", "ts-essentials", "ts-toolbelt", "hotscript", "hkt-toolbelt",
    // File processing
    "csv-parser", "csv-writer", "fast-csv", "papaparse", "xml2js", "xmlbuilder", "yamljs", "js-yaml",
    "toml", "ini", "properties", "properties-parser", "dotenv-expand", "dotenv-safe", "envfile",
    // Image & media processing  
    "sharp", "jimp", "gm", "imagemagick", "canvas", "fabric", "konva", "pixi.js", "p5", "processing-js",
    "tone", "howler", "pizzicato", "web-audio-api", "node-ffmpeg", "fluent-ffmpeg", "videojs", "plyr",
    // PDF & documents
    "pdfkit", "jspdf", "pdf-lib", "pdf2pic", "pdf-parse", "hummus-recipe", "officegen", "docxtemplater",
    "mammoth", "node-pandoc", "turndown", "showdown", "markdown-it", "marked", "commonmark", "remark",
    // Validation & parsing
    "validator", "is", "ow", "superstruct", "io-ts", "runtypes", "fastest-validator", "celebrate", "express-joi-validation",
    "multer", "@hapi/joi", "node-input-validator", "indicative", "vest", "calidation", "computed-types",
    // Caching & performance
    "memory-cache", "node-cache", "lru-cache", "flat-cache", "file-system-cache", "keyv", "cache-manager",
    "redis-cache", "memcached", "node-memcached", "compression", "express-compression", "shrink-ray-current",
    // Scheduling & jobs
    "node-cron", "cron", "agenda", "bull", "bee-queue", "kue", "resque", "node-resque", "later",
    // API & documentation  
    "swagger-jsdoc", "swagger-ui-express", "swagger-ui-dist", "redoc", "redoc-express", "apispec",
    "express-openapi", "fastify-swagger", "hapi-swagger", "@apidevtools/swagger-jsdoc", "yamljs",
    // Monitoring & logging
    "pino-pretty", "pino-http", "morgan", "express-winston", "log4js", "tracer", "caterpillar", "intel",
    "@google-cloud/logging", "@sentry/node", "rollbar", "bugsnag", "raygun", "airbrake-js", "honeybadger",
    // Development tools
    "lint-staged", "pretty-quick", "standard", "xo", "jshint", "jslint", "flow-bin", "@flow/cli",
    "flow-coverage-report", "nyc", "c8", "codecov", "coveralls", "codeclimate-test-reporter",
];

/// Top Java packages and standard library
const KNOWN_JAVA_PACKAGES: &[&str] = &[
    // Java Standard Library 
    "java.lang", "java.util", "java.io", "java.net", "java.nio", "java.sql", "java.time", "java.text", 
    "java.math", "java.security", "java.awt", "javax.swing", "java.applet", "java.beans", "java.rmi",
    "javax.servlet", "javax.servlet.http", "javax.xml", "javax.sql", "javax.crypto", "javax.net",
    "javax.imageio", "javax.sound", "javax.management", "javax.naming", "javax.transaction", 
    "javax.persistence", "javax.validation", "javax.annotation", "javax.inject", "javax.enterprise",
    // Popular frameworks and libraries
    "org.springframework", "org.springframework.boot", "org.springframework.web", "org.springframework.data",
    "org.springframework.security", "org.springframework.context", "org.springframework.beans",
    "com.google.gson", "com.google.guava", "com.google.common", "org.apache.commons", "org.apache.log4j",
    "org.apache.logging.log4j", "org.slf4j", "ch.qos.logback", "junit", "org.junit", "org.mockito",
    "org.testng", "org.apache.http", "org.apache.httpclient", "okhttp3", "retrofit2", "com.squareup",
    "org.hibernate", "org.mybatis", "org.apache.ibatis", "com.zaxxer.hikari", "org.h2", "mysql",
    "org.postgresql", "org.mongodb", "redis.clients.jedis", "org.apache.kafka", "org.apache.activemq",
    "com.rabbitmq", "org.apache.camel", "org.apache.cxf", "org.apache.poi", "org.apache.pdfbox",
    "com.itextpdf", "org.apache.lucene", "org.elasticsearch", "org.apache.solr", "com.fasterxml.jackson",
    "org.json", "org.yaml", "com.thoughtworks.xstream", "javax.xml.bind", "org.w3c.dom", "org.xml.sax",
    // Build tools and testing
    "org.gradle", "org.apache.maven", "org.apache.ant", "sbt", "org.scalatest", "org.specs2",
    "org.scalamock", "org.powermock", "org.easymock", "org.jmock", "org.hamcrest", "org.assertj",
    // Web frameworks
    "javax.ws.rs", "org.glassfish.jersey", "org.eclipse.jetty", "org.apache.tomcat", "org.jboss",
    "com.sun.jersey", "org.restlet", "spark.java", "io.javalin", "io.vertx", "com.vaadin",
    "org.primefaces", "org.richfaces", "org.icefaces", "org.zkoss", "org.apache.struts",
    "org.apache.wicket", "org.apache.tapestry", "play.api", "play.mvc", "akka", "com.typesafe",
    // Microservices and cloud
    "org.springframework.cloud", "org.springframework.boot.actuator", "io.micrometer", "io.dropwizard",
    "com.netflix.hystrix", "com.netflix.eureka", "com.netflix.zuul", "org.apache.dubbo", "io.grpc",
    "org.apache.thrift", "org.apache.avro", "org.apache.parquet", "org.apache.arrow", "org.apache.spark",
    "org.apache.flink", "org.apache.storm", "org.apache.hadoop", "org.apache.hive", "org.apache.pig",
    "org.apache.cassandra", "org.apache.hbase", "org.neo4j", "org.influxdb", "org.apache.zookeeper",
    // Android development
    "android", "androidx", "com.android", "android.app", "android.content", "android.view", 
    "android.widget", "android.os", "android.util", "com.google.android", "androidx.fragment",
    "androidx.recyclerview", "androidx.lifecycle", "androidx.navigation", "androidx.room",
    "androidx.work", "com.google.firebase", "com.squareup.picasso", "com.bumptech.glide",
    // Enterprise frameworks
    "javax.ejb", "javax.jms", "javax.mail", "org.apache.shiro", "org.keycloak", "org.jasig.cas",
    "org.opensaml", "org.pac4j", "org.apache.oltu", "com.auth0", "org.mitre", "org.wso2",
];

/// Top Go packages and standard library
const KNOWN_GO_PACKAGES: &[&str] = &[
    // Go standard library
    "fmt", "os", "io", "net", "net/http", "net/url", "encoding/json", "encoding/xml", "encoding/csv",
    "encoding/base64", "encoding/hex", "strings", "strconv", "regexp", "time", "math", "math/rand",
    "sort", "path", "path/filepath", "log", "errors", "context", "sync", "runtime", "reflect",
    "unsafe", "syscall", "crypto", "crypto/rand", "crypto/md5", "crypto/sha1", "crypto/sha256",
    "crypto/tls", "crypto/x509", "archive/tar", "archive/zip", "compress/gzip", "compress/flate",
    "bufio", "bytes", "container/list", "container/heap", "database/sql", "debug/pprof", "flag",
    "go/ast", "go/parser", "go/token", "html", "html/template", "image", "index/suffixarray",
    "mime", "mime/multipart", "net/mail", "net/rpc", "net/smtp", "net/textproto", "os/exec",
    "os/signal", "os/user", "plugin", "testing", "text/scanner", "text/tabwriter", "text/template",
    "unicode", "unicode/utf8", "unicode/utf16",
    // Popular third-party packages
    "github.com/gorilla/mux", "github.com/gin-gonic/gin", "github.com/labstack/echo", "github.com/fiber/fiber",
    "github.com/go-chi/chi", "github.com/julienschmidt/httprouter", "github.com/gorilla/websocket",
    "github.com/gorilla/sessions", "github.com/gorilla/handlers", "github.com/gorilla/csrf",
    "github.com/golang/protobuf", "google.golang.org/grpc", "google.golang.org/protobuf",
    "github.com/gorm.io/gorm", "github.com/jinzhu/gorm", "github.com/jmoiron/sqlx", "github.com/go-sql-driver/mysql",
    "github.com/lib/pq", "github.com/mattn/go-sqlite3", "github.com/go-redis/redis", "github.com/gomodule/redigo",
    "go.mongodb.org/mongo-driver", "github.com/olivere/elastic", "github.com/elastic/go-elasticsearch",
    "github.com/sirupsen/logrus", "go.uber.org/zap", "github.com/rs/zerolog", "github.com/op/go-logging",
    "github.com/spf13/cobra", "github.com/spf13/viper", "github.com/urfave/cli", "github.com/alecthomas/kingpin",
    "github.com/stretchr/testify", "github.com/golang/mock", "github.com/onsi/ginkgo", "github.com/onsi/gomega",
    "github.com/pkg/errors", "github.com/hashicorp/go-multierror", "golang.org/x/crypto", "golang.org/x/net",
    "golang.org/x/sync", "golang.org/x/time", "golang.org/x/text", "golang.org/x/sys", "golang.org/x/tools",
    "github.com/docker/docker", "k8s.io/client-go", "k8s.io/apimachinery", "k8s.io/api", "github.com/kubernetes/kubernetes",
    "github.com/hashicorp/consul", "github.com/hashicorp/vault", "github.com/etcd-io/etcd", "github.com/nats-io/nats.go",
    "github.com/streadway/amqp", "github.com/Shopify/sarama", "github.com/segmentio/kafka-go",
    "github.com/prometheus/client_golang", "github.com/opentracing/opentracing-go", "go.opentelemetry.io/otel",
    "github.com/jaegertracing/jaeger-client-go", "github.com/uber/jaeger-lib", "github.com/DataDog/dd-trace-go",
    "github.com/aws/aws-sdk-go", "cloud.google.com/go", "github.com/Azure/azure-sdk-for-go",
    "github.com/mitchellh/mapstructure", "github.com/fatih/color", "github.com/cheggaaa/pb", "github.com/briandowns/spinner",
];

/// Top Ruby gems and standard library
const KNOWN_RUBY_PACKAGES: &[&str] = &[
    // Ruby standard library
    "json", "yaml", "csv", "uri", "net/http", "net/https", "openssl", "digest", "base64", "zlib",
    "stringio", "tempfile", "fileutils", "pathname", "time", "date", "logger", "benchmark", "optparse",
    "ostruct", "singleton", "forwardable", "delegate", "observer", "timeout", "thread", "fiber",
    "mutex_m", "monitor", "sync", "drb", "xmlrpc", "rexml", "rss", "erb", "cgi", "webrick",
    // Popular Rails ecosystem
    "rails", "actionpack", "actionview", "actioncontroller", "actionmodel", "activerecord", "activesupport",
    "actionmailer", "actioncable", "activejob", "activestorage", "railties", "sprockets", "turbo-rails",
    "stimulus-rails", "importmap-rails", "cssbundling-rails", "jsbundling-rails", "image_processing",
    "bootsnap", "puma", "unicorn", "passenger", "thin", "webrick", "mongrel", "rack", "rack-test",
    "rack-cors", "rack-attack", "rack-timeout", "warden", "omniauth", "devise", "cancancan", "pundit",
    "rolify", "doorkeeper", "jwt", "bcrypt", "argon2", "scrypt", "rotp", "rqrcode",
    // Database and ORM
    "activerecord", "sequel", "datamapper", "mongoid", "mongo", "redis", "redis-namespace", "connection_pool",
    "pg", "mysql2", "sqlite3", "dalli", "memcached", "elasticsearch", "searchkick", "sunspot", "thinking-sphinx",
    "kaminari", "will_paginate", "ransack", "has_scope", "friendly_id", "paranoia", "acts_as_paranoid",
    "paper_trail", "audited", "public_activity", "acts-as-taggable-on", "acts_as_tree", "ancestry",
    // Testing frameworks
    "rspec", "rspec-core", "rspec-expectations", "rspec-mocks", "rspec-rails", "minitest", "test-unit",
    "factory_bot", "factory_bot_rails", "fabrication", "faker", "ffaker", "forgery", "database_cleaner",
    "webmock", "vcr", "timecop", "climate_control", "shoulda-matchers", "capybara", "selenium-webdriver",
    "site_prism", "cucumber", "cucumber-rails", "turnip", "guard", "guard-rspec", "guard-minitest",
    // Web frameworks (non-Rails)
    "sinatra", "padrino", "camping", "cuba", "roda", "hanami", "volt", "lotus", "grape", "goliath",
    "eventmachine", "celluloid", "concurrent-ruby", "async", "nio4r", "websocket-driver", "faye-websocket",
    // Background jobs
    "sidekiq", "resque", "delayed_job", "good_job", "solid_queue", "que", "sucker_punch", "whenever",
    "clockwork", "rufus-scheduler", "cron_parser", "chronic", "ice_cube",
    // HTTP clients and APIs
    "httparty", "faraday", "rest-client", "typhoeus", "curb", "net-http-persistent", "excon",
    "addressable", "public_suffix", "http", "http-form_data", "multipart-post", "mime-types",
    // File processing and utilities
    "nokogiri", "oga", "ox", "multi_xml", "multi_json", "yajl-ruby", "oj", "roxml", "happymapper",
    "carrierwave", "paperclip", "shrine", "mini_magick", "rmagick", "image_processing", "streamio-ffmpeg",
    "ruby-vips", "pdf-reader", "prawn", "prawn-table", "combine_pdf", "hexapdf", "wicked_pdf", "grover",
    // Configuration and environment
    "dotenv", "dotenv-rails", "figaro", "settingslogic", "config", "rails_config", "dry-configurable",
    "anyway_config", "chamber", "envyable", "climate_control",
    // Logging and monitoring
    "lograge", "logstash-logger", "semantic_logger", "logging", "log4r", "syslog-logger", "remote_syslog_logger",
    "newrelic_rpm", "skylight", "scout_apm", "appsignal", "bugsnag", "sentry-ruby", "sentry-rails",
    "rollbar", "airbrake", "exception_notification", "honeybadger",
    // Security
    "secure_headers", "rack-protection", "brakeman", "bundler-audit", "strong_parameters", "attr_encrypted",
    "lockbox", "symmetric-encryption", "rbnacl", "digest-crc", "rotp", "rqrcode", "ruby-saml",
];

/// Top C header files and common libraries
const KNOWN_C_PACKAGES: &[&str] = &[
    // C standard library
    "stdio.h", "stdlib.h", "string.h", "math.h", "time.h", "ctype.h", "limits.h", "float.h", "stddef.h",
    "stdarg.h", "setjmp.h", "signal.h", "errno.h", "locale.h", "assert.h", "stdint.h", "stdbool.h",
    "inttypes.h", "iso646.h", "wchar.h", "wctype.h", "complex.h", "fenv.h", "tgmath.h", "stdatomic.h",
    "stdnoreturn.h", "threads.h", "uchar.h",
    // POSIX headers
    "unistd.h", "sys/types.h", "sys/stat.h", "sys/wait.h", "sys/time.h", "sys/socket.h", "netinet/in.h",
    "arpa/inet.h", "netdb.h", "fcntl.h", "dirent.h", "pwd.h", "grp.h", "termios.h", "sys/ioctl.h",
    "sys/mman.h", "sys/shm.h", "sys/sem.h", "sys/msg.h", "pthread.h", "semaphore.h", "regex.h",
    // Common system libraries
    "sys/epoll.h", "sys/eventfd.h", "sys/timerfd.h", "sys/signalfd.h", "sys/inotify.h", "sys/prctl.h",
    "sys/resource.h", "sys/utsname.h", "sys/sysinfo.h", "linux/limits.h", "linux/version.h",
    // Popular C libraries
    "curl/curl.h", "openssl/ssl.h", "openssl/crypto.h", "openssl/evp.h", "openssl/rand.h", "zlib.h",
    "sqlite3.h", "mysql/mysql.h", "postgresql/libpq-fe.h", "glib.h", "gtk/gtk.h", "cairo.h",
    "json-c/json.h", "libxml/parser.h", "pcre.h", "readline/readline.h", "ncurses.h", "SDL.h",
    "allegro.h", "GLFW/glfw3.h", "GL/gl.h", "AL/al.h", "png.h", "jpeg.h", "tiff.h",
];

/// Top C++ headers and libraries
const KNOWN_CPP_PACKAGES: &[&str] = &[
    // C++ standard library
    "iostream", "iomanip", "fstream", "sstream", "string", "vector", "list", "deque", "stack", "queue",
    "priority_queue", "set", "multiset", "map", "multimap", "unordered_set", "unordered_map", "bitset",
    "algorithm", "numeric", "functional", "iterator", "memory", "utility", "tuple", "array", "forward_list",
    "unordered_set", "unordered_map", "random", "chrono", "regex", "thread", "mutex", "condition_variable",
    "future", "atomic", "exception", "stdexcept", "new", "typeinfo", "type_traits", "limits", "climits",
    "cfloat", "cstddef", "cstdlib", "cstring", "cmath", "ctime", "cctype", "cstdio", "cstdarg", "csetjmp",
    "csignal", "cerrno", "clocale", "cassert", "cstdint", "cinttypes", "cwchar", "cwctype", "ccomplex",
    "cfenv", "ctgmath", "cstdalign", "cstdbool", "cuchar",
    // Popular C++ libraries
    "boost/algorithm.hpp", "boost/asio.hpp", "boost/beast.hpp", "boost/filesystem.hpp", "boost/format.hpp",
    "boost/graph.hpp", "boost/lexical_cast.hpp", "boost/log.hpp", "boost/math.hpp", "boost/multi_index.hpp",
    "boost/property_tree.hpp", "boost/regex.hpp", "boost/serialization.hpp", "boost/signals2.hpp",
    "boost/spirit.hpp", "boost/system.hpp", "boost/test.hpp", "boost/thread.hpp", "boost/uuid.hpp",
    "eigen3/Eigen/Dense", "eigen3/Eigen/Sparse", "opencv2/opencv.hpp", "opencv2/core.hpp", "opencv2/imgproc.hpp",
    "opencv2/highgui.hpp", "opencv2/ml.hpp", "Qt5/QtCore", "Qt5/QtGui", "Qt5/QtWidgets", "Qt5/QtNetwork",
    "Qt5/QtSql", "Qt5/QtXml", "gtkmm.h", "wx/wx.h", "FLTK/FL.H", "allegro5/allegro.h", "SDL2/SDL.h",
    "GLFW/glfw3.h", "GL/glew.h", "vulkan/vulkan.h", "DirectXMath.h", "d3d11.h", "d3d12.h",
    "curl/curl.h", "openssl/ssl.h", "zlib.h", "sqlite3.h", "mysql/mysql.h", "postgresql/libpq-fe.h",
    "mongocxx/client.hpp", "bsoncxx/json.hpp", "redis++.h", "protobuf/message.h", "grpc++/grpc++.h",
    "json/json.h", "nlohmann/json.hpp", "rapidjson/document.h", "tinyxml2.h", "pugixml.hpp", "yaml-cpp/yaml.h",
    "gtest/gtest.h", "gmock/gmock.h", "catch2/catch.hpp", "doctest/doctest.h", "benchmark/benchmark.h",
    "fmt/format.h", "spdlog/spdlog.h", "plog/Log.h", "cpprestsdk/http_listener.h", "pistache/endpoint.h",
    "drogon/drogon.h", "crow.h", "restbed", "poco/Net/HTTPServer.h", "cpprest/http_listener.h",
    "asio.hpp", "websocketpp/config/asio_no_tls.hpp", "uws.h", "zmq.hpp", "nats.h", "amqp.h",
];

/// Top C# namespaces and packages
const KNOWN_CSHARP_PACKAGES: &[&str] = &[
    // .NET Base Class Library
    "System", "System.Collections", "System.Collections.Generic", "System.Collections.Concurrent", "System.Linq",
    "System.Text", "System.Text.RegularExpressions", "System.Text.Json", "System.IO", "System.IO.Compression",
    "System.Net", "System.Net.Http", "System.Net.Sockets", "System.Threading", "System.Threading.Tasks",
    "System.Reflection", "System.Runtime", "System.Runtime.Serialization", "System.Security", "System.Security.Cryptography",
    "System.Diagnostics", "System.ComponentModel", "System.Configuration", "System.Data", "System.Data.SqlClient",
    "System.Xml", "System.Xml.Linq", "System.Drawing", "System.Windows.Forms", "System.Web", "System.Web.Mvc",
    // .NET Core / .NET 5+
    "Microsoft.Extensions.DependencyInjection", "Microsoft.Extensions.Configuration", "Microsoft.Extensions.Logging",
    "Microsoft.Extensions.Hosting", "Microsoft.Extensions.Options", "Microsoft.Extensions.Caching",
    "Microsoft.AspNetCore", "Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Authorization", "Microsoft.AspNetCore.Authentication",
    "Microsoft.AspNetCore.Identity", "Microsoft.AspNetCore.SignalR", "Microsoft.AspNetCore.Blazor",
    "Microsoft.EntityFrameworkCore", "Microsoft.EntityFrameworkCore.SqlServer", "Microsoft.EntityFrameworkCore.Sqlite",
    "Microsoft.EntityFrameworkCore.InMemory", "Microsoft.EntityFrameworkCore.Design", "Microsoft.Data.SqlClient",
    // Popular NuGet packages
    "Newtonsoft.Json", "AutoMapper", "FluentValidation", "MediatR", "Serilog", "NLog", "log4net",
    "Dapper", "StackExchange.Redis", "MongoDB.Driver", "Npgsql", "MySql.Data", "Oracle.ManagedDataAccess",
    "RestSharp", "HttpClientFactory", "Polly", "Hangfire", "Quartz", "FluentScheduler", "NCrontab",
    "xUnit", "NUnit", "MSTest", "Moq", "NSubstitute", "FluentAssertions", "Shouldly", "AutoFixture",
    "BenchmarkDotNet", "NBomber", "SpecFlow", "Selenium.WebDriver", "Microsoft.Playwright",
    "Castle.Windsor", "Autofac", "Ninject", "Unity", "SimpleInjector", "StructureMap", "LightInject",
    "SignalR", "MassTransit", "NServiceBus", "Rebus", "EasyNetQ", "RabbitMQ.Client", "Confluent.Kafka",
    "WindowsAzure.Storage", "Azure.Storage.Blobs", "AWSSDK", "Google.Cloud", "Swashbuckle.AspNetCore",
    "IdentityServer4", "IdentityModel", "Microsoft.AspNetCore.Authentication.JwtBearer", "System.IdentityModel.Tokens.Jwt",
];

/// Top PHP packages and frameworks
const KNOWN_PHP_PACKAGES: &[&str] = &[
    // PHP built-in functions and classes (common prefixes)
    "array", "string", "file", "json", "curl", "date", "time", "hash", "crypt", "filter", "gd", "image",
    "mail", "mysqli", "pdo", "redis", "session", "xml", "zip", "openssl", "mcrypt", "mb", "iconv",
    "preg", "pcre", "spl", "reflection", "iterator", "exception", "error", "stream", "socket",
    // Laravel ecosystem
    "illuminate", "laravel", "artisan", "eloquent", "blade", "facade", "middleware", "migration", "seeder",
    "factory", "policy", "rule", "request", "response", "resource", "collection", "carbon", "tinker",
    "horizon", "telescope", "sanctum", "passport", "socialite", "cashier", "scout", "dusk", "envoy",
    // Symfony ecosystem
    "symfony", "console", "http-foundation", "http-kernel", "routing", "dependency-injection", "event-dispatcher",
    "form", "validator", "serializer", "translation", "templating", "security", "doctrine", "twig",
    "monolog", "swiftmailer", "assetic", "sensio", "knp", "friendsofsymfony", "sonata",
    // Other popular frameworks
    "codeigniter", "cakephp", "zend", "laminas", "yii", "phalcon", "slim", "lumen", "silex", "kohana",
    "fuel", "lithium", "aura", "nette", "pimcore", "drupal", "wordpress", "joomla", "magento", "prestashop",
    // Composer packages
    "composer", "autoload", "vendor", "psr", "fig", "phpunit", "phpspec", "behat", "codeception", "mockery",
    "prophecy", "faker", "carbon", "nesbot", "ramsey", "uuid", "guzzle", "guzzlehttp", "httplug", "psr7",
    "league", "thephpleague", "vlucas", "phpdotenv", "intervention", "imagine", "gregwar", "avalanche",
    "knplabs", "pagerfanta", "white-october", "sensiolabs", "easycorp", "webmozart", "sebastian",
    "phpstan", "psalm", "rector", "cs-fixer", "php-cs-fixer", "squizlabs", "codesniffer", "roave",
    "ocramius", "doctrine", "orm", "dbal", "migrations", "annotations", "cache", "common", "collections",
    "predis", "phpredis", "mongodb", "elasticsearch", "solr", "sphinx", "memcached", "memcache",
    "twig", "smarty", "plates", "mustache", "handlebars", "parsedown", "michelf", "erusev", "commonmark",
    "swiftmailer", "phpmailer", "zendmail", "mail", "mime", "message", "transport", "mailer",
];

/// Top Swift frameworks and libraries
const KNOWN_SWIFT_PACKAGES: &[&str] = &[
    // Swift Standard Library
    "Swift", "Foundation", "Dispatch", "os", "Darwin", "Glibc", "WinSDK",
    // iOS/macOS/watchOS/tvOS frameworks
    "UIKit", "AppKit", "WatchKit", "TVUIKit", "SwiftUI", "Combine", "RealityKit", "ARKit", "CoreML",
    "CreateML", "Vision", "NaturalLanguage", "Speech", "SoundAnalysis", "CoreMotion", "HealthKit",
    "HomeKit", "EventKit", "Contacts", "ContactsUI", "MessageUI", "Social", "Accounts", "CloudKit",
    "CoreData", "CoreGraphics", "CoreImage", "CoreVideo", "CoreMedia", "CoreAudio", "AudioToolbox",
    "AVFoundation", "MediaPlayer", "Photos", "PhotosUI", "CoreLocation", "MapKit", "CoreBluetooth",
    "ExternalAccessory", "GameKit", "GameplayKit", "SpriteKit", "SceneKit", "Metal", "MetalKit",
    "CoreAnimation", "QuartzCore", "WebKit", "SafariServices", "StoreKit", "AdSupport", "iAd",
    "NetworkExtension", "Network", "CFNetwork", "Security", "CryptoKit", "CommonCrypto", "LocalAuthentication",
    "DeviceCheck", "UserNotifications", "NotificationCenter", "CallKit", "ReplayKit", "FileProvider",
    // Popular Swift Package Manager packages
    "Alamofire", "AFNetworking", "Kingfisher", "SDWebImage", "SnapKit", "Masonry", "RxSwift", "RxCocoa",
    "ReactiveCocoa", "ReactiveSwift", "PromiseKit", "BrightFutures", "Result", "Then", "SwiftyJSON",
    "ObjectMapper", "Codable", "SwiftProtobuf", "GRDB", "SQLite.swift", "Realm", "RealmSwift", "CoreStore",
    "Firebase", "FirebaseAuth", "FirebaseFirestore", "FirebaseDatabase", "FirebaseStorage", "FirebaseMessaging",
    "FirebaseAnalytics", "FirebaseCrashlytics", "GoogleSignIn", "FBSDKLoginKit", "TwitterKit", "LinkedInSignIn",
    "Charts", "SwiftCharts", "PNChart", "JBChartView", "FSCalendar", "CVCalendar", "JTCalendar",
    "Lottie", "Hero", "Material", "MaterialComponents", "FlexLayout", "LayoutKit", "PinLayout",
    "Stevia", "EasyPeasy", "Cartography", "TinyConstraints", "SwiftAutoLayout", "SnapKit", "Anchorage",
    "SwiftGen", "R.swift", "SwiftLint", "SwiftFormat", "Sourcery", "XcodeGen", "Tuist", "Mint",
    "Quick", "Nimble", "OCMock", "OCMockito", "Cuckoo", "SwiftCheck", "Hamcrest", "Expecta",
    // Networking and API
    "URLSession", "NSURLSession", "Moya", "Siesta", "Just", "SwiftHTTP", "Perfect", "Vapor", "Kitura",
    "SwiftNIO", "AsyncHTTPClient", "WebSocketKit", "SocketRocket", "Starscream", "Socket.IO-Client-Swift",
];

/// Top Kotlin libraries and frameworks
const KNOWN_KOTLIN_PACKAGES: &[&str] = &[
    // Kotlin standard library
    "kotlin", "kotlin.collections", "kotlin.text", "kotlin.io", "kotlin.math", "kotlin.random", "kotlin.time",
    "kotlin.coroutines", "kotlinx.coroutines", "kotlin.sequences", "kotlin.ranges", "kotlin.comparisons",
    "kotlin.concurrent", "kotlin.contracts", "kotlin.experimental", "kotlin.properties", "kotlin.reflect",
    "kotlin.annotation", "kotlin.jvm", "kotlin.js", "kotlin.native", "kotlin.system",
    // Android specific
    "android", "androidx", "com.android", "android.app", "android.content", "android.view", "android.widget",
    "android.os", "android.util", "androidx.activity", "androidx.fragment", "androidx.lifecycle", "androidx.navigation",
    "androidx.recyclerview", "androidx.room", "androidx.work", "androidx.compose", "androidx.hilt",
    "com.google.android.material", "androidx.viewpager2", "androidx.cardview", "androidx.constraintlayout",
    "androidx.swiperefreshlayout", "androidx.appcompat", "androidx.core", "androidx.preference",
    // Popular Kotlin libraries
    "kotlinx.serialization", "kotlinx.datetime", "kotlinx.html", "kotlinx.css", "kotlinx.cli",
    "com.squareup.okhttp3", "com.squareup.retrofit2", "com.squareup.moshi", "com.google.gson", 
    "com.fasterxml.jackson", "io.ktor", "org.jetbrains.exposed", "org.jetbrains.kotlinx",
    "arrow-kt", "arrow.core", "arrow.fx", "arrow.optics", "arrow.meta", "io.arrow-kt",
    "org.kodein.di", "org.koin", "dagger", "dagger.hilt", "com.google.dagger", "javax.inject",
    "kotlinx.coroutines.android", "kotlinx.coroutines.core", "kotlinx.coroutines.reactive", "kotlinx.coroutines.rx2",
    "io.reactivex.rxjava2", "io.reactivex.rxjava3", "io.reactivex.rxkotlin", "io.reactivex.rxandroid",
    "com.jakewharton.timber", "org.slf4j", "ch.qos.logback", "io.github.microutils", "mu.KotlinLogging",
    // Testing frameworks
    "org.junit", "junit", "org.jetbrains.spek", "io.kotest", "org.amshove.kluent", "com.natpryce.hamkrest",
    "io.mockk", "com.nhaarman.mockitokotlin2", "org.mockito", "com.google.truth", "org.assertj",
    "androidx.test", "androidx.test.espresso", "androidx.test.ext.junit", "org.robolectric",
    // Web frameworks
    "io.ktor.server", "io.ktor.client", "io.ktor.serialization", "org.springframework.boot", "org.springframework",
    "io.micronaut", "io.quarkus", "com.github.javalin", "org.http4k", "ratpack", "spark.kotlin",
    // Database and ORM
    "org.jetbrains.exposed.sql", "org.jetbrains.exposed.dao", "org.jetbrains.exposed.jdbc",
    "androidx.room.runtime", "androidx.room.ktx", "com.squareup.sqldelight", "com.github.jasync-sql",
    "org.mongodb.kotlin", "redis.clients.jedis", "io.lettuce", "org.neo4j.driver", "org.influxdb",
];

/// Top R packages and libraries
const KNOWN_R_PACKAGES: &[&str] = &[
    // Base R packages (always loaded)
    "base", "utils", "stats", "graphics", "grDevices", "methods", "datasets", "tools", "parallel",
    "compiler", "splines", "tcltk", "stats4", "grid", "boot", "class", "cluster", "codetools",
    "foreign", "KernSmooth", "lattice", "mgcv", "nlme", "nnet", "rpart", "spatial", "survival", "MASS",
    // Core tidyverse
    "ggplot2", "dplyr", "tidyr", "readr", "purrr", "tibble", "stringr", "forcats", "tidyverse",
    "magrittr", "rlang", "glue", "lifecycle", "vctrs", "cli", "crayon", "pillar", "hms",
    // Data manipulation
    "data.table", "reshape2", "plyr", "janitor", "broom", "tidyselect", "tidymodels", "recipes",
    "rsample", "parsnip", "workflows", "tune", "dials", "yardstick", "workflowsets", "finetune",
    // Statistical modeling
    "caret", "randomForest", "e1071", "glmnet", "xgboost", "lightgbm", "catboost", "gbm", "rpart",
    "tree", "party", "partykit", "ranger", "Boruta", "VIM", "mice", "Hmisc", "psych", "corrplot",
    "FactoMineR", "factoextra", "cluster", "fpc", "dbscan", "flexclust", "mixtools", "EMCluster",
    // Visualization
    "plotly", "shiny", "shinydashboard", "shinyWidgets", "DT", "leaflet", "visNetwork", "networkD3",
    "gganimate", "ggrepel", "ggthemes", "ggridges", "patchwork", "cowplot", "gridExtra", "latticeExtra",
    "corrplot", "pheatmap", "ComplexHeatmap", "circlize", "VennDiagram", "UpSetR", "treemap", "wordcloud",
    // Time series
    "forecast", "prophet", "zoo", "xts", "ts", "TSA", "tseries", "urca", "vars", "quantmod",
    "tidyquant", "timetk", "sweep", "anomalize", "tibbletime", "padr", "imputeTS", "seasonal",
    // Bioinformatics
    "Biobase", "BiocGenerics", "S4Vectors", "IRanges", "GenomicRanges", "Biostrings", "GenomicFeatures",
    "GenomicAlignments", "Rsamtools", "rtracklayer", "AnnotationDbi", "org.Hs.eg.db", "GO.db",
    "DESeq2", "edgeR", "limma", "affy", "oligo", "GEOquery", "Bioconductor", "BiocManager",
    // Web scraping and APIs
    "rvest", "xml2", "httr", "jsonlite", "RCurl", "curl", "robotstxt", "polite", "RSelenium",
    "webdriver", "chromote", "pagedown", "blogdown", "pkgdown", "bookdown", "xaringan", "flexdashboard",
    // Database connectivity
    "DBI", "RSQLite", "RMySQL", "RPostgreSQL", "RMariaDB", "odbc", "RODBC", "mongolite", "RMongo",
    "redis", "RRedis", "sparklyr", "dbplyr", "pool", "keyring", "config", "here",
    // Spatial analysis
    "sf", "sp", "raster", "rgdal", "rgeos", "maptools", "maps", "mapdata", "ggmap", "tmap",
    "leaflet", "mapview", "rnaturalearth", "osmdata", "tigris", "tidycensus", "censusapi",
    // Text mining
    "tm", "quanteda", "tidytext", "textdata", "SnowballC", "wordcloud", "RColorBrewer", "topicmodels",
    "text2vec", "glmnet", "stm", "lda", "LDAvis", "syuzhet", "sentimentr", "vader", "textclean",
    // Package development
    "devtools", "usethis", "pkgbuild", "pkgload", "remotes", "roxygen2", "testthat", "covr",
    "lintr", "styler", "goodpractice", "rhub", "pkgdown", "badger", "lifecycle", "rlang",
];

/// Top MQL5 functions and indicators
const KNOWN_MQL5_PACKAGES: &[&str] = &[
    // Trading functions
    "OrderSend", "OrderClose", "OrderModify", "OrderDelete", "OrderSelect", "OrdersTotal", "OrderTicket",
    "OrderType", "OrderLots", "OrderOpenPrice", "OrderClosePrice", "OrderStopLoss", "OrderTakeProfit",
    "OrderProfit", "OrderCommission", "OrderSwap", "OrderSymbol", "OrderMagicNumber", "OrderOpenTime",
    "OrderCloseTime", "OrderExpiration", "OrderComment", "OrderPrint", "PositionSelect", "PositionGetInteger",
    "PositionGetDouble", "PositionGetString", "PositionsTotal", "HistorySelect", "HistoryOrderSelect",
    "HistoryOrderGetInteger", "HistoryOrderGetDouble", "HistoryOrderGetString", "HistoryOrdersTotal",
    "HistoryDealSelect", "HistoryDealGetInteger", "HistoryDealGetDouble", "HistoryDealGetString", "HistoryDealsTotal",
    // Market data functions
    "MarketInfo", "SymbolSelect", "SymbolsTotal", "SymbolName", "SymbolInfoInteger", "SymbolInfoDouble",
    "SymbolInfoString", "SymbolInfoTick", "SymbolInfoSessionQuote", "SymbolInfoSessionTrade", "CopyRates",
    "CopyTime", "CopyOpen", "CopyHigh", "CopyLow", "CopyClose", "CopyTickVolume", "CopyRealVolume",
    "CopySpread", "CopyBuffer", "iOpen", "iHigh", "iLow", "iClose", "iVolume", "iTime", "Bars", "iBars",
    // Technical indicators
    "iMA", "iMACD", "iRSI", "iStochastic", "iBands", "iATR", "iCCI", "iDeMarker", "iEnvelopes", "iForce",
    "iMomentum", "iOsMA", "iSAR", "iStdDev", "iWPR", "iAC", "iAD", "iADX", "iAlligator", "iAO", "iBearsPower",
    "iBullsPower", "iCustom", "iFractals", "iGator", "iIchimoku", "iBWMFI", "iMFI", "iOBV", "iROC", "iRVI",
    "iTriX", "iVIDyA", "iVolumes", "ChartIndicatorAdd", "ChartIndicatorDelete", "ChartIndicatorGet",
    // Account functions
    "AccountBalance", "AccountCredit", "AccountCompany", "AccountCurrency", "AccountEquity", "AccountFreeMargin",
    "AccountFreeMarginCheck", "AccountFreeMarginMode", "AccountLeverage", "AccountMargin", "AccountName",
    "AccountNumber", "AccountProfit", "AccountServer", "AccountStopoutLevel", "AccountStopoutMode",
    "AccountInfoInteger", "AccountInfoDouble", "AccountInfoString",
    // Time functions
    "TimeCurrent", "TimeLocal", "TimeGMT", "TimeDaylightSavings", "TimeGMTOffset", "TimeToString", "TimeToStruct",
    "StructToTime", "TimeDay", "TimeDayOfWeek", "TimeDayOfYear", "TimeHour", "TimeMinute", "TimeMonth",
    "TimeSeconds", "TimeYear", "StringToTime", "TimeTradeServer",
    // String functions
    "StringAdd", "StringBufferLen", "StringCompare", "StringConcatenate", "StringFill", "StringFind", "StringGetCharacter",
    "StringInit", "StringLen", "StringReplace", "StringSetCharacter", "StringSubstr", "StringToLower", "StringToUpper",
    "StringTrimLeft", "StringTrimRight", "StringToCharArray", "CharArrayToString", "ShortToString", "ShortArrayToString",
    "IntegerToString", "IntegerToHexString", "DoubleToString", "NormalizeDouble", "StringFormat",
    // Math functions
    "MathAbs", "MathArccos", "MathArcsin", "MathArctan", "MathCeil", "MathCos", "MathExp", "MathFloor", "MathLog",
    "MathMax", "MathMin", "MathMod", "MathPow", "MathRand", "MathRound", "MathSin", "MathSqrt", "MathSrand", "MathTan",
    "MathIsValidNumber", "MathExpm1", "MathLog1p", "MathArccosh", "MathArcsinh", "MathArctanh", "MathCosh", "MathSinh", "MathTanh",
    // File functions
    "FileOpen", "FileClose", "FileDelete", "FileFlush", "FileGetInteger", "FileIsEnding", "FileIsExist", "FileIsLineEnding",
    "FileMove", "FileReadArray", "FileReadBool", "FileReadDatetime", "FileReadDouble", "FileReadFloat", "FileReadInteger",
    "FileReadLong", "FileReadNumber", "FileReadString", "FileReadStruct", "FileSeek", "FileSize", "FileTell",
    "FileWrite", "FileWriteArray", "FileWriteDouble", "FileWriteFloat", "FileWriteInteger", "FileWriteLong", "FileWriteString", "FileWriteStruct",
    "FolderCreate", "FolderDelete", "FolderClean", "FileCopy", "FileSelectDialog",
];

/// Top Scala libraries and frameworks
const KNOWN_SCALA_PACKAGES: &[&str] = &[
    // Scala standard library
    "scala", "scala.collection", "scala.util", "scala.concurrent", "scala.io", "scala.math", "scala.reflect",
    "scala.annotation", "scala.beans", "scala.compat", "scala.runtime", "scala.sys", "scala.text", "scala.xml",
    "scala.collection.mutable", "scala.collection.immutable", "scala.collection.generic", "scala.collection.parallel",
    "scala.util.control", "scala.util.matching", "scala.util.parsing", "scala.concurrent.duration",
    "scala.concurrent.forkjoin", "java.util", "java.lang", "java.io", "java.util.concurrent",
    // Akka ecosystem
    "akka", "akka.actor", "akka.stream", "akka.http", "akka.cluster", "akka.persistence", "akka.testkit",
    "akka.remote", "akka.routing", "akka.pattern", "akka.util", "akka.event", "akka.dispatch",
    "akka.actor.typed", "akka.stream.scaladsl", "akka.http.scaladsl", "akka.cluster.sharding",
    "akka.persistence.query", "akka.management", "akka.discovery", "akka.serialization",
    // Play framework
    "play.api", "play.api.mvc", "play.api.db", "play.api.cache", "play.api.libs", "play.api.test",
    "play.api.data", "play.api.i18n", "play.api.routing", "play.api.inject", "play.api.libs.json",
    "play.api.libs.ws", "play.api.libs.mailer", "play.api.libs.openid", "play.api.libs.oauth",
    "controllers", "models", "views", "Global", "filters", "services",
    // Cats ecosystem
    "cats", "cats.effect", "cats.data", "cats.syntax", "cats.instances", "cats.implicits", "cats.kernel",
    "cats.laws", "cats.testkit", "cats.arrow", "cats.free", "cats.mtl", "cats.tagless",
    "cats.effect.IO", "cats.effect.Sync", "cats.effect.Async", "cats.effect.Resource", "cats.effect.Bracket",
    // Functional programming libraries
    "scalaz", "scalaz.syntax", "scalaz.std", "scalaz.concurrent", "scalaz.stream", "scalaz.effect",
    "fs2", "fs2.io", "fs2.concurrent", "monix", "monix.eval", "monix.reactive", "monix.execution",
    "shapeless", "shapeless.syntax", "shapeless.ops", "refined", "refined.api", "refined.auto",
    // JSON libraries
    "circe", "circe.syntax", "circe.parser", "circe.generic", "circe.optics", "argonaut", "argonaut.Argonaut",
    "play.api.libs.json", "upickle", "ujson", "json4s", "json4s.jackson", "json4s.native", "spray.json",
    // HTTP clients and servers
    "sttp", "sttp.client3", "sttp.model", "requests", "scalaj.http", "dispatch", "AsyncHttpClient",
    "http4s", "http4s.dsl", "http4s.server", "http4s.client", "http4s.circe", "http4s.blaze",
    "finch", "finch.syntax", "twitter.finatra", "twitter.finagle", "twitter.util",
    // Database libraries
    "slick", "slick.jdbc", "slick.driver", "slick.lifted", "doobie", "doobie.implicits",
    "doobie.postgres", "doobie.h2", "quill", "quill.context", "anorm", "squeryl",
    "reactivemongo", "reactivemongo.api", "sangria", "sangria.schema", "sangria.execution",
    // Testing frameworks
    "scalatest", "scalatest.flatspec", "scalatest.wordspec", "scalatest.funspec", "scalatest.matchers",
    "scalacheck", "scalacheck.Gen", "scalacheck.Arbitrary", "specs2", "specs2.mutable", "utest",
    "testcontainers", "testcontainers.scala", "mockito", "scalamock",
    // Big data libraries
    "spark", "org.apache.spark", "org.apache.spark.sql", "org.apache.spark.streaming", "org.apache.spark.ml",
    "org.apache.spark.mllib", "org.apache.spark.rdd", "org.apache.spark.broadcast", "breeze", "breeze.linalg",
    "breeze.numerics", "breeze.stats", "smile", "smile.clustering", "smile.classification", "smile.regression",
    // Configuration and logging
    "com.typesafe.config", "pureconfig", "pureconfig.generic", "logback", "slf4j", "scalaLogging",
    "com.typesafe.scalalogging", "akka.event.Logging", "play.api.Logger",
    // Utility libraries
    "better.files", "ammonite", "ammonite.ops", "fastparse", "scopt", "decline", "enumeratum",
    "spire", "spire.math", "spire.algebra", "squants", "monocle", "monocle.macros", "chimney",
];

/// Top Perl modules and pragmas
const KNOWN_PERL_PACKAGES: &[&str] = &[
    // Core pragmas and modules
    "strict", "warnings", "utf8", "feature", "autodie", "constant", "vars", "lib", "base", "parent",
    "Exporter", "Carp", "Data::Dumper", "Scalar::Util", "List::Util", "List::MoreUtils", "File::Spec",
    "File::Basename", "File::Path", "File::Find", "File::Copy", "File::Temp", "File::Slurp", "IO::File",
    "IO::Handle", "IO::Socket", "IO::Select", "Getopt::Long", "Getopt::Std", "Pod::Usage", "FindBin",
    "English", "POSIX", "Config", "Errno", "Fcntl", "Socket", "Symbol", "SelectSaver", "FileHandle",
    // Popular CPAN modules
    "Moose", "Moo", "Mouse", "Class::Tiny", "Object::Tiny", "Class::Accessor", "Class::Struct",
    "Method::Signatures", "Function::Parameters", "Try::Tiny", "TryCatch", "Exception::Class",
    "Throwable", "namespace::clean", "namespace::autoclean", "MRO::Compat", "Class::C3",
    "DBI", "DBD::mysql", "DBD::Pg", "DBD::SQLite", "DBD::Oracle", "DBIx::Class", "Rose::DB",
    "SQL::Abstract", "SQL::Interp", "MongoDB", "Redis", "Memcached::Client", "Cache::Memcached",
    "LWP", "LWP::UserAgent", "HTTP::Request", "HTTP::Response", "URI", "URI::Escape", "JSON", "JSON::XS",
    "YAML", "YAML::XS", "XML::LibXML", "XML::Simple", "XML::Twig", "HTML::Parser", "Web::Scraper",
    "Mojo", "Mojolicious", "Mojolicious::Lite", "Catalyst", "Dancer", "Dancer2", "Plack", "PSGI",
    "CGI", "CGI::Application", "Template", "Template::Toolkit", "HTML::Template", "Text::Template",
    "DateTime", "Date::Calc", "Date::Manip", "Time::HiRes", "Time::Piece", "Time::Local",
    "Digest::MD5", "Digest::SHA", "Crypt::CBC", "Crypt::Blowfish", "Crypt::DES", "Crypt::SSLeay",
    "Net::SSH2", "Net::SFTP", "Net::FTP", "Net::SMTP", "Net::POP3", "Net::IMAP::Simple", "Email::Simple",
    "Email::MIME", "Email::Sender", "MIME::Lite", "Mail::Sendmail", "Log::Log4perl", "Log::Dispatch",
    "Config::General", "Config::Simple", "Config::Tiny", "AppConfig", "Getopt::Long::Descriptive",
    "Path::Tiny", "Path::Class", "File::HomeDir", "File::Which", "File::ShareDir", "Archive::Zip",
    "Archive::Tar", "Compress::Zlib", "IO::Compress::Gzip", "Text::CSV", "Text::CSV_XS", "Spreadsheet::ParseExcel",
    "PDF::API2", "CAM::PDF", "Image::Magick", "Imager", "GD", "Chart::Gnuplot", "Statistics::Descriptive",
    "Math::Random", "Math::BigInt", "Math::BigFloat", "Number::Format", "Regexp::Common", "Perl6::Slurp",
    "IPC::Run", "IPC::System::Simple", "Parallel::ForkManager", "threads", "Thread::Queue", "MCE",
    "Test::More", "Test::Simple", "Test::Exception", "Test::Warn", "Test::MockObject", "Test::Class",
    "Devel::Cover", "Devel::NYTProf", "Benchmark", "Modern::Perl", "common::sense", "experimental",
];

/// Top Lua modules and libraries
const KNOWN_LUA_PACKAGES: &[&str] = &[
    // Lua standard library
    "string", "table", "math", "io", "os", "coroutine", "package", "debug", "utf8",
    // Popular Lua libraries
    "socket", "lfs", "lpeg", "rex", "cjson", "dkjson", "inspect", "penlight", "pl", "luafilesystem",
    "luasocket", "luasec", "luacrypto", "luaposix", "lanes", "copas", "coxpcall", "rings", "uuid",
    "md5", "sha1", "base64", "mime", "ltn12", "url", "ftp", "http", "smtp", "tp", "luasql",
    "luadbi", "luarocks", "busted", "luaunit", "telescope", "say", "luassert", "moonscript",
    "etlua", "lustache", "cosmo", "saci", "orbit", "sailor", "lapis", "openresty", "nginx",
    "torch", "nn", "image", "optim", "gnuplot", "mattorch", "cutorch", "cunn", "cudnn",
    "redis", "memcached", "mongodb", "elasticsearch", "rabbitmq", "zeromq", "nanomsg", "msgpack",
    "protobuf", "capnproto", "flatbuffers", "bson", "yaml", "toml", "ini", "csv", "xml", "html",
    "curl", "requests", "http_digest", "oauth", "jwt", "bcrypt", "argon2", "scrypt", "hmac",
    "love", "löve", "corona", "gideros", "defold", "awesome", "wireshark", "vlc", "lighttpd",
    "nginx", "apache", "haproxy", "kong", "openresty", "luvit", "luv", "libuv", "ffi", "bit",
];

/// Top Dart packages and frameworks  
const KNOWN_DART_PACKAGES: &[&str] = &[
    // Dart core libraries
    "dart:core", "dart:async", "dart:collection", "dart:convert", "dart:developer", "dart:ffi", "dart:html",
    "dart:indexed_db", "dart:io", "dart:isolate", "dart:js", "dart:js_util", "dart:math", "dart:mirrors",
    "dart:svg", "dart:typed_data", "dart:ui", "dart:web_audio", "dart:web_gl", "dart:web_sql",
    // Flutter framework
    "flutter", "flutter/material.dart", "flutter/cupertino.dart", "flutter/widgets.dart", "flutter/animation.dart",
    "flutter/foundation.dart", "flutter/gestures.dart", "flutter/painting.dart", "flutter/physics.dart",
    "flutter/rendering.dart", "flutter/scheduler.dart", "flutter/semantics.dart", "flutter/services.dart",
    "flutter_test", "flutter_driver", "integration_test", "flutter_web_plugins", "flutter_localizations",
    // State management
    "provider", "riverpod", "flutter_riverpod", "hooks_riverpod", "bloc", "flutter_bloc", "cubit",
    "get", "getx", "mobx", "flutter_mobx", "redux", "flutter_redux", "built_redux", "fish_redux",
    "states_rebuilder", "easy_notifier", "scoped_model", "inherited_widget", "change_notifier",
    // Networking and HTTP
    "http", "dio", "chopper", "retrofit", "graphql", "graphql_flutter", "ferry", "websocket_channel",
    "socket_io", "socket_io_client", "web_socket_channel", "sse", "grpc", "protobuf", "fixnum",
    // Database and storage
    "sqflite", "drift", "moor", "floor", "objectbox", "realm", "hive", "hive_flutter", "get_storage",
    "shared_preferences", "flutter_secure_storage", "path_provider", "sembast", "isar", "firebase_firestore",
    "cloud_firestore", "firebase_database", "firebase_storage", "cloud_storage", "sqlite3", "postgres",
    // UI and animation
    "animations", "lottie", "rive", "flare_flutter", "nima", "auto_size_text", "flutter_staggered_grid_view",
    "flutter_staggered_animations", "shimmer", "skeleton_text", "loading_animation_widget", "spinkit",
    "flutter_spinkit", "cached_network_image", "flutter_svg", "flutter_launcher_icons", "flutter_native_splash",
    "badges", "carousel_slider", "page_view_indicators", "dots_indicator", "smooth_page_indicator",
    "flutter_swiper", "card_swiper", "introduction_screen", "flutter_onboarding_slider", "onboarding",
    // Forms and input
    "flutter_form_builder", "form_builder_validators", "reactive_forms", "flutter_hooks", "formz",
    "validators", "mask_text_input_formatter", "flutter_masked_text", "pin_code_fields", "otp_text_field",
    // Navigation and routing
    "go_router", "auto_route", "fluro", "routemaster", "beamer", "vrouter", "page_transition",
    "flutter_page_transition", "modal_bottom_sheet", "flutter_modular", "get_it", "injectable",
    // Firebase and backend services
    "firebase_core", "firebase_auth", "firebase_analytics", "firebase_messaging", "firebase_crashlytics",
    "firebase_performance", "firebase_remote_config", "firebase_dynamic_links", "firebase_ml_vision",
    "cloud_functions", "supabase", "supabase_flutter", "appwrite", "parse_server_sdk_flutter",
    "amplify_flutter", "aws_amplify", "pocketbase", "convex_flutter",
    // Utilities and helpers
    "intl", "collection", "meta", "equatable", "json_annotation", "json_serializable", "built_value",
    "freezed", "dartz", "fpdart", "kt_dart", "uuid", "crypto", "convert", "path", "mime", "archive",
    "logging", "stack_trace", "source_span", "args", "yaml", "xml", "csv", "html", "markdown",
    // Testing
    "test", "mockito", "build_runner", "build_test", "fake_async", "clock", "matcher", "boolean_selector",
    "coverage", "test_coverage", "integration_test", "flutter_gherkin", "patrol", "golden_toolkit",
    // Platform integration
    "url_launcher", "share", "device_info", "package_info", "app_settings", "permission_handler",
    "geolocator", "location", "camera", "image_picker", "file_picker", "flutter_contacts", "battery_plus",
    "connectivity_plus", "network_info_plus", "device_info_plus", "sensors_plus", "vibration",
];

/// Top Haskell packages and libraries
const KNOWN_HASKELL_PACKAGES: &[&str] = &[
    // Base and core libraries
    "Prelude", "Data.List", "Data.Maybe", "Data.Either", "Control.Monad", "Control.Applicative",
    "Data.Function", "Data.Tuple", "Data.Bool", "Data.Char", "Data.Int", "Data.Word", "Data.Ord",
    "Data.Eq", "Data.Show", "Data.Read", "Data.Enum", "Data.Bounded", "Data.Ix", "Data.Array",
    "Data.String", "Data.Monoid", "Data.Semigroup", "Data.Functor", "Data.Foldable", "Data.Traversable",
    "Control.Monad.IO.Class", "Control.Monad.Trans.Class", "Control.Monad.Trans", "Control.Exception",
    "System.IO", "System.Environment", "System.Exit", "System.Process", "System.FilePath", "System.Directory",
    "Text.Printf", "Text.Read", "Text.Show.Functions", "Debug.Trace", "GHC.Generics", "Data.Typeable",
    "Data.Data", "Control.DeepSeq", "Data.IORef", "Data.STRef", "Control.Concurrent", "Control.Parallel",
    // Popular libraries
    "text", "bytestring", "containers", "unordered-containers", "vector", "hashable", "deepseq",
    "transformers", "mtl", "stm", "async", "parallel", "random", "QuickCheck", "HUnit", "hspec",
    "tasty", "criterion", "time", "directory", "filepath", "process", "unix", "Win32", "network",
    "HTTP", "http-types", "wai", "warp", "snap", "scotty", "servant", "yesod", "happstack", "spock",
    "aeson", "yaml", "cassava", "xml", "html", "blaze-html", "lucid", "pandoc", "markdown",
    "parsec", "megaparsec", "attoparsec", "trifecta", "regex-base", "regex-posix", "regex-pcre",
    "lens", "optics", "profunctors", "comonad", "free", "pipes", "conduit", "streaming", "machines",
    "resourcet", "exceptions", "safe-exceptions", "unliftio", "rio", "classy-prelude", "protolude",
    "foundation", "relude", "universum", "basic-prelude", "custom-prelude", "streaming-commons",
    "monad-control", "lifted-base", "lifted-async", "monad-logger", "fast-logger", "hslogger",
    "cryptonite", "crypto-api", "tls", "x509", "pem", "asn1-types", "certificate", "connection",
    "postgresql-simple", "mysql-simple", "sqlite-simple", "persistent", "esqueleto", "selda",
    "opaleye", "rel8", "beam", "groundhog", "acid-state", "safecopy", "cereal", "binary", "store",
    "redis", "hedis", "mongodb", "bson", "cassandra-cql", "cql", "neo4j-client", "influxdb",
    "scotty", "servant-server", "servant-client", "wai-extra", "wai-cors", "wai-middleware-static",
    "wreq", "req", "http-client", "http-client-tls", "http-conduit", "simple-http", "download",
    "optparse-applicative", "cmdargs", "system-filepath", "turtle", "shelly", "shell-conduit",
    "temporary", "extra", "utility-ht", "data-default", "split", "MissingH", "utility-ht", "safe",
];

/// Code analyzer for detecting issues in source code
pub struct CodeAnalyzer {
    security_patterns: Vec<SecurityPattern>,
    hallucination_patterns: Vec<HallucinationPattern>,
    custom_allowlist: Option<CustomAllowlist>,
}

struct SecurityPattern {
    name: &'static str,
    regex: Regex,
    severity: Severity,
    message: &'static str,
}

struct HallucinationPattern {
    name: &'static str,
    regex: Regex,
    check_imports: fn(&str) -> bool,
}

impl Default for CodeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeAnalyzer {
    pub fn new() -> Self {
        Self::with_custom_allowlist(None)
    }

    pub fn with_custom_allowlist(custom_allowlist: Option<CustomAllowlist>) -> Self {
        let security_patterns = vec![
            SecurityPattern {
                name: "eval_usage",
                regex: Regex::new(r"\beval\s*\(").unwrap(),
                severity: Severity::High,
                message: "Potentially dangerous eval() usage detected",
            },
            SecurityPattern {
                name: "exec_usage", 
                regex: Regex::new(r"\bexec\s*\(").unwrap(),
                severity: Severity::High,
                message: "Potentially dangerous exec() usage detected",
            },
            SecurityPattern {
                name: "system_calls",
                regex: Regex::new(r"(subprocess\.call|subprocess\.run|os\.system|os\.popen|shell_exec|system\(|exec\(|passthru\(|shell_exec\()").unwrap(),
                severity: Severity::Medium,
                message: "System call detected - verify input sanitization",
            },
            SecurityPattern {
                name: "hardcoded_secrets",
                regex: Regex::new(r#"(password|secret|key|token)\s*[=:]\s*["'][^"']{8,}["']"#).unwrap(),
                severity: Severity::High,
                message: "Potential hardcoded secret detected",
            },
            SecurityPattern {
                name: "api_keys",
                regex: Regex::new(r#"(API_KEY|SECRET_KEY|ACCESS_TOKEN|PRIVATE_KEY)\s*[=:]\s*["'][^"']+["']"#).unwrap(),
                severity: Severity::Critical,
                message: "Hardcoded API key or secret detected",
            },
            SecurityPattern {
                name: "sql_injection",
                regex: Regex::new(r#"(execute\(|query\(|sql\s*=)[^;]*\+[^;]*["']"#).unwrap(),
                severity: Severity::High,
                message: "Potential SQL injection vulnerability - string concatenation in SQL",
            },
            SecurityPattern {
                name: "shell_injection",
                regex: Regex::new(r"subprocess\.[^(]*\([^)]*shell\s*=\s*True").unwrap(),
                severity: Severity::High,
                message: "Shell injection risk - subprocess with shell=True",
            },
            SecurityPattern {
                name: "insecure_http",
                regex: Regex::new(r#"["']http://[^"'\s]+["']?"#).unwrap(),
                severity: Severity::Medium,
                message: "Insecure HTTP URL found - consider using HTTPS",
            },
            SecurityPattern {
                name: "rm_rf",
                regex: Regex::new(r"rm\s+-rf\s+").unwrap(),
                severity: Severity::Critical,
                message: "Dangerous rm -rf command detected",
            },
            SecurityPattern {
                name: "chmod_777",
                regex: Regex::new(r"chmod\s+(777|0777)").unwrap(),
                severity: Severity::High,
                message: "Dangerous chmod 777 permissions detected",
            },
            SecurityPattern {
                name: "ssl_verify_disabled",
                regex: Regex::new(r"(verify\s*=\s*False|SSL_VERIFYPEER.*false|curl_setopt.*CURLOPT_SSL_VERIFYPEER.*false)").unwrap(),
                severity: Severity::High,
                message: "SSL certificate verification disabled",
            },
            SecurityPattern {
                name: "dangerous_deserialize",
                regex: Regex::new(r"(pickle\.loads|pickle\.load|yaml\.load\(|eval\(|exec\()").unwrap(),
                severity: Severity::High,
                message: "Potentially unsafe deserialization method",
            },
        ];

        let hallucination_patterns = vec![
            HallucinationPattern {
                name: "python_imports",
                regex: Regex::new(r"(?m)^(?:from\s+(\w+(?:\.\w+)*)|import\s+(\w+(?:\.\w+)*))").unwrap(),
                check_imports: |package| {
                    let base_package = package.split('.').next().unwrap_or(package);
                    !KNOWN_PYTHON_PACKAGES.contains(&base_package)
                },
            },
            HallucinationPattern {
                name: "js_imports",
                regex: Regex::new(r#"(?:import.*?from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\))"#).unwrap(),
                check_imports: |package| {
                    // Handle scoped packages and relative imports
                    if package.starts_with('.') || package.starts_with('/') {
                        return false; // Relative imports are fine
                    }
                    let base_package = if package.starts_with('@') {
                        package.split('/').take(2).collect::<Vec<_>>().join("/")
                    } else {
                        package.split('/').next().unwrap_or(package).to_string()
                    };
                    !KNOWN_JS_PACKAGES.contains(&base_package.as_str())
                },
            },
            HallucinationPattern {
                name: "java_imports",
                regex: Regex::new(r"import\s+(static\s+)?([a-zA-Z_][a-zA-Z0-9_.]*(?:\.\*)?);").unwrap(),
                check_imports: |package| {
                    let base_package = package.split('.').take(2).collect::<Vec<_>>().join(".");
                    !KNOWN_JAVA_PACKAGES.contains(&base_package.as_str())
                },
            },
            HallucinationPattern {
                name: "go_imports",
                regex: Regex::new(r#"import\s+(?:"([^"]+)"|([a-zA-Z_][a-zA-Z0-9_./]*)|(?:\(\s*(?:"[^"]+"\s*)+\)))"#).unwrap(),
                check_imports: |package| {
                    let clean_package = package.trim_matches('"');
                    if clean_package.contains(".") {
                        return !KNOWN_GO_PACKAGES.iter().any(|&known| clean_package.contains(known));
                    }
                    !KNOWN_GO_PACKAGES.contains(&clean_package)
                },
            },
            HallucinationPattern {
                name: "ruby_requires",
                regex: Regex::new(r#"(?:require|gem)\s+['"]([^'"]+)['"]"#).unwrap(),
                check_imports: |package| {
                    let base_package = package.split('/').next().unwrap_or(package);
                    !KNOWN_RUBY_PACKAGES.contains(&base_package)
                },
            },
            HallucinationPattern {
                name: "c_includes",
                regex: Regex::new(r#"#include\s+[<"]([^>"]+)[>"]"#).unwrap(),
                check_imports: |package| {
                    !KNOWN_C_PACKAGES.contains(&package)
                },
            },
            HallucinationPattern {
                name: "cpp_includes",
                regex: Regex::new(r#"#include\s+[<"]([^>"]+)[>"]"#).unwrap(),
                check_imports: |package| {
                    !KNOWN_CPP_PACKAGES.contains(&package) && !KNOWN_C_PACKAGES.contains(&package)
                },
            },
            HallucinationPattern {
                name: "csharp_using",
                regex: Regex::new(r"using\s+([a-zA-Z_][a-zA-Z0-9_.]*);").unwrap(),
                check_imports: |package| {
                    let base_package = if package.contains('.') {
                        package.split('.').take(2).collect::<Vec<_>>().join(".")
                    } else {
                        package.to_string()
                    };
                    !KNOWN_CSHARP_PACKAGES.contains(&base_package.as_str())
                },
            },
            HallucinationPattern {
                name: "php_use",
                regex: Regex::new(r"(?:use|require_once|include_once|require|include)\s+([a-zA-Z_\\][a-zA-Z0-9_\\]*);?").unwrap(),
                check_imports: |package| {
                    let base_package = package.split('\\').next().unwrap_or(package).to_lowercase();
                    !KNOWN_PHP_PACKAGES.contains(&base_package.as_str())
                },
            },
            HallucinationPattern {
                name: "swift_import",
                regex: Regex::new(r"import\s+([a-zA-Z_][a-zA-Z0-9_]*)").unwrap(),
                check_imports: |package| {
                    !KNOWN_SWIFT_PACKAGES.contains(&package)
                },
            },
            HallucinationPattern {
                name: "kotlin_import",
                regex: Regex::new(r"import\s+([a-zA-Z_][a-zA-Z0-9_.]*)").unwrap(),
                check_imports: |package| {
                    let base_package = package.split('.').take(2).collect::<Vec<_>>().join(".");
                    !KNOWN_KOTLIN_PACKAGES.contains(&base_package.as_str())
                },
            },
            HallucinationPattern {
                name: "r_library",
                regex: Regex::new(r#"(?:library|require)\s*\(\s*['"]?([a-zA-Z_][a-zA-Z0-9_.]*?)['"]?\s*\)"#).unwrap(),
                check_imports: |package| {
                    !KNOWN_R_PACKAGES.contains(&package)
                },
            },
            HallucinationPattern {
                name: "scala_import",
                regex: Regex::new(r"import\s+([a-zA-Z_][a-zA-Z0-9_.]*)").unwrap(),
                check_imports: |package| {
                    let base_package = package.split('.').take(2).collect::<Vec<_>>().join(".");
                    !KNOWN_SCALA_PACKAGES.contains(&base_package.as_str())
                },
            },
            HallucinationPattern {
                name: "perl_use",
                regex: Regex::new(r"(?:use|require)\s+([a-zA-Z_][a-zA-Z0-9_:]*);?").unwrap(),
                check_imports: |package| {
                    let base_package = package.split("::").next().unwrap_or(package);
                    !KNOWN_PERL_PACKAGES.contains(&base_package)
                },
            },
            HallucinationPattern {
                name: "lua_require",
                regex: Regex::new(r#"require\s*\(?['"]([^'"]+)['"]"#).unwrap(),
                check_imports: |package| {
                    let base_package = package.split('.').next().unwrap_or(package);
                    !KNOWN_LUA_PACKAGES.contains(&base_package)
                },
            },
            HallucinationPattern {
                name: "dart_import",
                regex: Regex::new(r#"import\s+['"]([^'"]+)['"]"#).unwrap(),
                check_imports: |package| {
                    if package.starts_with("dart:") {
                        return !KNOWN_DART_PACKAGES.contains(&package);
                    }
                    let base_package = package.split('/').next().unwrap_or(package);
                    !KNOWN_DART_PACKAGES.contains(&base_package)
                },
            },
            HallucinationPattern {
                name: "haskell_import",
                regex: Regex::new(r"import\s+(?:qualified\s+)?([a-zA-Z_][a-zA-Z0-9_.]*)").unwrap(),
                check_imports: |package| {
                    let base_package = package.split('.').take(2).collect::<Vec<_>>().join(".");
                    !KNOWN_HASKELL_PACKAGES.contains(&base_package.as_str())
                },
            },
        ];

        CodeAnalyzer {
            security_patterns,
            hallucination_patterns,
            custom_allowlist,
        }
    }
    
    /// Load custom allowlist from .vow/known-packages.yaml
    pub fn load_custom_allowlist() -> Option<CustomAllowlist> {
        let custom_path = Path::new(".vow/known-packages.yaml");
        if custom_path.exists() {
            match std::fs::read_to_string(custom_path) {
                Ok(content) => match serde_yaml::from_str::<CustomAllowlist>(&content) {
                    Ok(allowlist) => Some(allowlist),
                    Err(e) => {
                        eprintln!("Warning: Failed to parse .vow/known-packages.yaml: {}", e);
                        None
                    }
                },
                Err(e) => {
                    eprintln!("Warning: Failed to read .vow/known-packages.yaml: {}", e);
                    None
                }
            }
        } else {
            None
        }
    }

    /// Check if a package is in the custom allowlist
    fn is_custom_allowed(&self, package: &str, file_type: &FileType) -> bool {
        if let Some(ref allowlist) = self.custom_allowlist {
            match file_type {
                FileType::Python => {
                    if let Some(ref python_packages) = allowlist.python {
                        return python_packages.iter().any(|p| p == package);
                    }
                }
                FileType::JavaScript | FileType::TypeScript => {
                    if let Some(ref js_packages) = allowlist.javascript {
                        return js_packages.iter().any(|p| {
                            // Handle scoped packages - match either the full name or just the scope
                            p == package || (package.starts_with('@') && p.starts_with(&package.split('/').next().unwrap_or("")))
                        });
                    }
                }
                FileType::Java => {
                    if let Some(ref packages) = allowlist.java {
                        return packages.iter().any(|p| p == package);
                    }
                }
                FileType::Go => {
                    if let Some(ref packages) = allowlist.go {
                        return packages.iter().any(|p| package.contains(p));
                    }
                }
                FileType::Ruby => {
                    if let Some(ref packages) = allowlist.ruby {
                        return packages.iter().any(|p| p == package);
                    }
                }
                FileType::C => {
                    if let Some(ref packages) = allowlist.c {
                        return packages.iter().any(|p| p == package);
                    }
                }
                FileType::Cpp => {
                    if let Some(ref packages) = allowlist.cpp {
                        return packages.iter().any(|p| p == package);
                    }
                }
                FileType::CSharp => {
                    if let Some(ref packages) = allowlist.csharp {
                        return packages.iter().any(|p| p == package);
                    }
                }
                FileType::PHP => {
                    if let Some(ref packages) = allowlist.php {
                        return packages.iter().any(|p| p == package);
                    }
                }
                FileType::Swift => {
                    if let Some(ref packages) = allowlist.swift {
                        return packages.iter().any(|p| p == package);
                    }
                }
                FileType::Kotlin => {
                    if let Some(ref packages) = allowlist.kotlin {
                        return packages.iter().any(|p| p == package);
                    }
                }
                FileType::R => {
                    if let Some(ref packages) = allowlist.r {
                        return packages.iter().any(|p| p == package);
                    }
                }
                FileType::MQL5 => {
                    if let Some(ref packages) = allowlist.mql5 {
                        return packages.iter().any(|p| p == package);
                    }
                }
                FileType::Scala => {
                    if let Some(ref packages) = allowlist.scala {
                        return packages.iter().any(|p| p == package);
                    }
                }
                FileType::Perl => {
                    if let Some(ref packages) = allowlist.perl {
                        return packages.iter().any(|p| p == package);
                    }
                }
                FileType::Lua => {
                    if let Some(ref packages) = allowlist.lua {
                        return packages.iter().any(|p| p == package);
                    }
                }
                FileType::Dart => {
                    if let Some(ref packages) = allowlist.dart {
                        return packages.iter().any(|p| p == package);
                    }
                }
                FileType::Haskell => {
                    if let Some(ref packages) = allowlist.haskell {
                        return packages.iter().any(|p| p == package);
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Analyze code file for potential issues
    pub fn analyze(&self, path: &Path, content: &str) -> AnalysisResult {
        let file_type = detect_code_type(path);
        let mut issues = Vec::new();
        
        // Run security pattern detection
        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.security_patterns {
                if pattern.regex.is_match(line) {
                    issues.push(Issue {
                        severity: pattern.severity.clone(),
                        message: pattern.message.to_string(),
                        line: Some(line_num + 1),
                        rule: Some(pattern.name.to_string()),
                    });
                }
            }
        }
        
        // Run hallucinated API detection
        self.detect_hallucinated_apis(content, &file_type, &mut issues);
        
        AnalysisResult {
            path: path.to_path_buf(),
            file_type: file_type.clone(),
            issues,
            trust_score: 100, // Will be recalculated in lib.rs
        }
    }
    
    fn detect_hallucinated_apis(&self, content: &str, file_type: &FileType, issues: &mut Vec<Issue>) {
        let pattern_name = match file_type {
            FileType::Python => "python_imports",
            FileType::JavaScript | FileType::TypeScript => "js_imports",
            FileType::Java => "java_imports",
            FileType::Go => "go_imports",
            FileType::Ruby => "ruby_requires",
            FileType::C => "c_includes",
            FileType::Cpp => "cpp_includes",
            FileType::CSharp => "csharp_using",
            FileType::PHP => "php_use",
            FileType::Swift => "swift_import",
            FileType::Kotlin => "kotlin_import",
            FileType::R => "r_library",
            FileType::MQL5 => return, // MQL5 has built-in functions, not imports
            FileType::Scala => "scala_import",
            FileType::Perl => "perl_use",
            FileType::Lua => "lua_require",
            FileType::Dart => "dart_import",
            FileType::Haskell => "haskell_import",
            _ => return,
        };
        
        let pattern = self.hallucination_patterns.iter().find(|p| p.name == pattern_name);
        
        if let Some(pattern) = pattern {
            for (line_num, line) in content.lines().enumerate() {
                for captures in pattern.regex.captures_iter(line) {
                    // Get the package name from either capture group
                    let package = captures.get(1).or_else(|| captures.get(2))
                        .map(|m| m.as_str())
                        .unwrap_or("");
                    
                    if !package.is_empty() {
                        // Check built-in packages first
                        let is_known = (pattern.check_imports)(package);
                        // Then check custom allowlist
                        let is_custom_allowed = self.is_custom_allowed(package, file_type);
                        
                        if is_known && !is_custom_allowed {
                            issues.push(Issue {
                                severity: Severity::Medium,
                                message: format!("Potentially hallucinated package import: '{}'", package),
                                line: Some(line_num + 1),
                                rule: Some("hallucinated_api".to_string()),
                            });
                        }
                    }
                }
            }
        }
    }
}

fn detect_code_type(path: &Path) -> FileType {
    if let Some(extension) = path.extension().and_then(|s| s.to_str()) {
        match extension.to_lowercase().as_str() {
            "py" => FileType::Python,
            "js" | "jsx" => FileType::JavaScript,
            "ts" | "tsx" => FileType::TypeScript,
            "rs" => FileType::Rust,
            "java" => FileType::Java,
            "go" => FileType::Go,
            "rb" => FileType::Ruby,
            "c" | "h" => FileType::C,
            "cpp" | "cc" | "cxx" | "hpp" => FileType::Cpp,
            "cs" => FileType::CSharp,
            "php" => FileType::PHP,
            "swift" => FileType::Swift,
            "kt" | "kts" => FileType::Kotlin,
            "r" => FileType::R,
            "mq5" | "mqh" => FileType::MQL5,
            "scala" => FileType::Scala,
            "pl" | "pm" => FileType::Perl,
            "lua" => FileType::Lua,
            "dart" => FileType::Dart,
            "hs" => FileType::Haskell,
            _ => FileType::Unknown,
        }
    } else {
        FileType::Unknown
    }
}