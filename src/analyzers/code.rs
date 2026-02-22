use std::path::Path;
use crate::{AnalysisResult, Issue, Severity, FileType};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct CustomAllowlist {
    pub python: Option<Vec<String>>,
    pub javascript: Option<Vec<String>>,
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
        let pattern = match file_type {
            FileType::Python => self.hallucination_patterns.iter().find(|p| p.name == "python_imports"),
            FileType::JavaScript | FileType::TypeScript => self.hallucination_patterns.iter().find(|p| p.name == "js_imports"),
            _ => return,
        };
        
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
            _ => FileType::Unknown,
        }
    } else {
        FileType::Unknown
    }
}