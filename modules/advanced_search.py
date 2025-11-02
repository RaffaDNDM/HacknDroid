"""
This source file is part of the HacknDroid project.

Licensed under the Apache License v2.0
"""

import regex
import os
import sys
from concurrent.futures import ProcessPoolExecutor
from termcolor import colored
import csv
from collections import defaultdict
from tabulate import tabulate
from modules.utility import current_date

SECRETS_REGEX = {
    "API Key Generic Detector": {
     "regex": regex.compile(b'(apikey|api_key|secret|token)[\'"\s:=]+[a-zA-Z0-9\-._]{8,}', flags=regex.IGNORECASE),
     "light_search": False,
     },

    "API Key in Variable": {
        "regex": regex.compile(b'(api[_-]?key)[\'"\s:=]+[a-zA-Z0-9\-_.]{8,100}', flags=0),
        "light_search": True,
    },
    "Algolia API Key": {
        "regex": regex.compile(b'(algolia|application)_?key[\'"\s:=]+[a-zA-Z0-9]{10,}', flags=regex.IGNORECASE),
        "light_search": True,
    },
    "Amazon AWS Access Key ID": {
        "regex": regex.compile(b'([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}', flags=0),
        "light_search": True,
    },
    "Amazon AWS IAM Role ARN": {
        "regex": regex.compile(b'arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9_+=,.@\-_/]+', flags=0),
        "light_search": True,
    },
    "Amazon AWS RDS Hostname": {
        "regex": regex.compile(b'[a-z0-9-]+\.rds\.amazonaws\.com', flags=0),
        "light_search": True,
    },
    "Amazon AWS S3 Bucket": [
        {
            "regex": regex.compile(b'//s3-[a-z0-9-]+\.amazonaws\.com/[a-z0-9._-]+', flags=0),
            "light_search": True,
        },
        {
            "regex": regex.compile(b'//s3\.amazonaws\.com/[a-z0-9._-]+', flags=0),
            "light_search": True,
        },
        {
            "regex": regex.compile(b'[a-z0-9.-]+\.s3-[a-z0-9-]\.amazonaws\.com', flags=0),
            "light_search": True,
        },
        {
            "regex": regex.compile(b'[a-z0-9.-]+\.s3-website[.-](eu|ap|us|ca|sa|cn)', flags=0),
            "light_search": True,
        },
        {
            "regex": regex.compile(b'[a-z0-9.-]+\.s3\.amazonaws\.com', flags=0),
            "light_search": True,
        },
        {
            "regex": regex.compile(b's3:\/\/[a-z0-9\-\.]{3,63}', flags=0),
            "light_search": True,
        },
    ],
    "Amazon AWS Secret Key": {
        "regex": regex.compile(b'[0-9a-zA-Z/+]{40}', flags=0),
        "light_search": False,
    },
    "Amazon AWS_API_Key": {
        "regex": regex.compile(b'AKIA[0-9A-Z]{16}', flags=0),
        "light_search": True,
    },
    "Amazon Marketing Services": {
        "regex": regex.compile(b'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', flags=0),
        "light_search": True,
    },
    "Amplitude API Key": {
        "regex": regex.compile(b'apiKey[\'"]?\s*:\s*[\'"][a-z0-9\-]{32,64}[\'"]', flags=0),
        "light_search": True,
    },
    "Artifactory API Token": {
        "regex": regex.compile(b'(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}', flags=0),
        "light_search": True,
    },
    "Artifactory Password": {
        "regex": regex.compile(b'(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}', flags=0),
        "light_search": True,
    },
    "Asana Personal Access Token": {
        "regex": regex.compile(b'0/[0-9a-z]{32}', flags=0),
        "light_search": True,
    },
    "Auth0_Client_ID": {
        "regex": regex.compile(b'[0-9a-zA-Z]{32}', flags=0),
        "light_search": False,
    },
    "Auth0_Client_Secret": {
        "regex": regex.compile(b'[0-9a-zA-Z]{64}', flags=0),
        "light_search": False,
    },
    "Authorization Bearer Token": {
        "regex": regex.compile(b'[b|B]earer\s+[a-zA-Z0-9\-._~+/]+=*', flags=0),
        "light_search": True,
    },
    "Authorization Basic": {
        "regex": regex.compile(b'basic\s[a-zA-Z0-9_\-:\.=]+', flags=0),
        "light_search": True,
    },
    "Azure Client Secret": {
        "regex": regex.compile(b'azure(.{0,20})?client.secret(.{0,20})?[\'"][a-zA-Z0-9._%+-]{32,}[\'"]', flags=regex.IGNORECASE),
        "light_search": True,
    },
    "Azure DevOps Token": {
        "regex": regex.compile(b'[a-z0-9]{52}', flags=0),
        "light_search": False,
    },
    "Base64": {
        "regex": regex.compile(b'^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$', flags=0),
        "light_search": True,
    },
    "Base64 High Entropy String": {
        "regex": regex.compile(b'[\'"][A-Za-z0-9+\/]{40,}={0,2}[\'"]', flags=0),
        "light_search": False,
    },
    "Basic Auth String": {
        "regex": regex.compile(b'(username|user|email)[\'"\s:=]+[^\s\'"@]{1,100}[\'"].*?(password|pwd)[\'"\s:=]+[^\s\'"]{4,100}', flags=regex.IGNORECASE),
        "light_search": False,
    },
    "Basic Auth Credentials": {
        "regex": regex.compile(b'(?<=:\/\/)[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+', flags=0),
        "light_search": True,
    },
    "Bearer Token Generic": {
        "regex": regex.compile(b'authorization:\s*Bearer\s+[a-zA-Z0-9\-._~+/]+=*', flags=regex.IGNORECASE),
        "light_search": True,
    },
    "BigIP Cookie": {
        "regex": regex.compile(b'^BIGipServer[a-zA-Z0-9_-]+=[0-9]+\.[0-9]+\.[0-9]+$', flags=0),
        "light_search": True,
    },
    "Bitbucket OAuth Key": {
        "regex": regex.compile(b'bitbucket(.{0,20})?key[\'"\s:=]+[a-zA-Z0-9]{20,}', flags=0),
        "light_search": True,
    },
    "Bitbucket OAuth Secret": {
        "regex": regex.compile(b'bitbucket(.{0,20})?secret[\'"\s:=]+[a-zA-Z0-9]{20,}', flags=0),
        "light_search": True,
    },
    "Bugsnag API Key": {
        "regex": regex.compile(b'[a-f0-9]{32}', flags=0),
        "light_search": False,
    },
    "CircleCI Token": {
        "regex": regex.compile(b'circle-token=[a-z0-9]{40}', flags=0),
        "light_search": True,
    },
    "Cloud SQL URI (GCP)": {
        "regex": regex.compile(b'googleapis\.com\/sql\/v1beta4\/projects\/', flags=0),
        "light_search": True,
    },
    "Cloudinary_Basic_Auth": {
        "regex": regex.compile(b'cloudinary:\/\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+', flags=0),
        "light_search": True,
    },
    "Cookie Name Generic": {
        "regex": regex.compile(b'set-cookie:\s*[a-zA-Z0-9_-]+=', flags=regex.IGNORECASE),
        "light_search": True,
    },
    "Datadog API Key": {
        "regex": regex.compile(b'[a-z0-9]{32}', flags=0),
        "light_search": False,
    },
    "Dev/Stage URL": {
        "regex": regex.compile(b'(dev|staging|test)\.[a-z0-9.-]+\.(com|net|io)', flags=0),
        "light_search": True,
    },
    "DigitalOcean Token": {
        "regex": regex.compile(b'dop_v1_[a-z0-9]{64}', flags=0),
        "light_search": True,
    },
    "Discord Bot Token": [
        {
            "regex": regex.compile(b'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}', flags=0),
            "light_search": True,
        },
        {
            "regex": regex.compile(b'((?:N|M|O)[a-zA-Z0-9]{23}\.[a-zA-Z0-9-_]{6}\.[a-zA-Z0-9-_]{27})$', flags=0),
            "light_search": True,
        },
    ],
    "Discord Webhook URL": {
        "regex": regex.compile(b'https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+', flags=0),
        "light_search": True,
    },
    "Docker Hub Password": {
        "regex": regex.compile(b'docker(.{0,20})?password[\'"\s:=]+[^\s\'"]{8,}', flags=regex.IGNORECASE),
        "light_search": True,
    },
    "Dropbox Access Token": {
        "regex": regex.compile(b'sl.[A-Za-z0-9_-]{20,100}', flags=0),
        "light_search": False,
    },
    "Dropbox_API_Key": {
        "regex": regex.compile(b'[a-zA-Z0-9]{15}', flags=0),
        "light_search": False,
    },
    "Dropbox_API_Secret": {
        "regex": regex.compile(b'[a-zA-Z0-9]{32}', flags=0),
        "light_search": False,
    },
    "Elasticsearch URI": {
        "regex": regex.compile(b'elasticsearch:\/\/[^\s\'"]+', flags=0),
        "light_search": True,
    },
    "Facebook AccessToken": {
        "regex": regex.compile(b'EAACEdEose0cBA[0-9A-Za-z]+', flags=0),
        "light_search": True,
    },
    "Facebook ClientID": {
        "regex": regex.compile(b'[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K](.{0,20})?[\'"][0-9]{13,17}', flags=0),
        "light_search": True,
    },
    "Facebook OAuth": {
        "regex": regex.compile(b'[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*[\'|"][0-9a-f]{32}[\'|"]', flags=0),
        "light_search": True,
    },
    "Facebook SecretKey": {
        "regex": regex.compile(b'([f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K]|[f|F][b|B])(.{0,20})?[\'"][0-9a-f]{32}', flags=0),
        "light_search": True,
    },
    "Firebase": [
        {
            "regex": regex.compile(b'[a-z0-9.-]+\.firebaseio\.com', flags=0),
            "light_search": True,
        },
        {
            "regex": regex.compile(b'https:\/\/[a-z0-9-]+\.firebaseio\.com', flags=0),
            "light_search": True,
        },
    ],
    "Firebase API Key": {
        "regex": regex.compile(b'firebaseConfig\s*=\s*{[^}]*apiKey\s*:\s*[\'"][^\'"]+[\'"]', flags=0),
        "light_search": True,
    },
    "Foursquare Client Key": {
        "regex": regex.compile(b'[0-9a-zA-Z_][5,31]', flags=0),
        "light_search": False,
    },
    "Foursquare Secret Key": {
        "regex": regex.compile(b'R_[0-9a-f]{32}', flags=0),
        "light_search": True,
    },
    "Generic API Key": {
        "regex": regex.compile(b'[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*[\'|"][0-9a-zA-Z]{32,45}[\'|"]', flags=0),
        "light_search": True,
    },
    "Generic Secret": {
        "regex": regex.compile(b'[s|S][e|E][c|C][r|R][e|E][t|T].*[\'|"][0-9a-zA-Z]{32,45}[\'|"]', flags=0),
        "light_search": True,
    },
    "GitHub": {
        "regex": regex.compile(b'[g|G][i|I][t|T][h|H][u|U][b|B].*[\'|"][0-9a-zA-Z]{35,40}[\'|"]', flags=0),
        "light_search": True,
    },
    "GitHub Actions Encrypted Value": {
        "regex": regex.compile(b'encrypted_value:\s*[\'"][a-zA-Z0-9+/=]{10,}[\'"]', flags=0),
        "light_search": True,
    },
    "GitHub Actions Secret Reference": {
        "regex": regex.compile(b'secrets\.[A-Z0-9_]+', flags=0),
        "light_search": True,
    },
    "GitHub OAuth App Secret": {
        "regex": regex.compile(b'[a-f0-9]{40}', flags=0),
        "light_search": False,
    },
    "GitHub Access Token": {
        "regex": regex.compile(b'([a-zA-Z0-9_-]*:[a-zA-Z0-9_-]+@github.com*)$', flags=0),
        "light_search": True,
    },
    "GitLab Personal Access Token": {
        "regex": regex.compile(b'glpat-[0-9a-zA-Z-_]{20}', flags=0),
        "light_search": True,
    },
    "GitLab Runner Token": {
        "regex": regex.compile(b'glrt-[a-zA-Z0-9_-]{20}', flags=0),
        "light_search": True,
    },
    "Github OAuth 2.0 Access Token": {
        "regex": regex.compile(b'^gho_[a-zA-Z0-9]{36}$', flags=0),
        "light_search": True,
    },
    "Github Personal Access Token (Classic)": {
        "regex": regex.compile(b'^ghp_[a-zA-Z0-9]{36}$', flags=0),
        "light_search": True,
    },
    "Github Personal Access Token (Fine-Grained)": {
        "regex": regex.compile(b'^github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}$', flags=0),
        "light_search": True,
    },
    "Github Refresh Token": {
        "regex": regex.compile(b'^ghr_[a-zA-Z0-9]{36}$', flags=0),
        "light_search": True,
    },
    "Github Server-to-Server Access Token": {
        "regex": regex.compile(b'^ghs_[a-zA-Z0-9]{36}$', flags=0),
        "light_search": True,
    },
    "Github User-to-Server Access Token": {
        "regex": regex.compile(b'^ghu_[a-zA-Z0-9]{36}$', flags=0),
        "light_search": True,
    },
    "Google_API_Key": {
        "regex": regex.compile(b'AIza[0-9A-Za-z\-_]{35}', flags=0),
        "light_search": True,
    },
    "Google Cloud Platform API Key": {
        "regex": regex.compile(b'[A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}', flags=0),
        "light_search": True,
    },
    "Google Cloud Platform OAuth": {
        "regex": regex.compile(b'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', flags=0),
        "light_search": True,
    },
    "Google Cloud Platform OAuth 2.0": {
        "regex": regex.compile(b'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', flags=0),
        "light_search": True,
    },
    "Google Cloud Platform ServiceAccount": {
        "regex": regex.compile(b'\"type\": \"service_account\"', flags=0),
        "light_search": True,
    },
    "Google OAuth 2.0 Auth Code": {
        "regex": regex.compile(b'4/[0-9A-Za-z-_]+', flags=0),
        "light_search": False,
    },
    "Google OAuth 2.0 Refresh Token": {
        "regex": regex.compile(b'1/[0-9A-Za-z-]{43}|1/[0-9A-Za-z-]{64}', flags=0),
        "light_search": True,
    },
    "Google OAuth 2.0 Secret Key": {
        "regex": regex.compile(b'[0-9a-zA-Z-_]{24}', flags=0),
        "light_search": False,
    },
    "Google OAuth Access Token": {
        "regex": regex.compile(b'ya29\.[0-9A-Za-z\-_]+', flags=0),
        "light_search": False,
    },
    "Hashicorp Vault URL": {
        "regex": regex.compile(b'https:\/\/vault\.[a-z0-9\-_\.]+\.com', flags=0),
        "light_search": True,
    },
    "Heap Analytics App ID": {
        "regex": regex.compile(b'heapSettings\.appId\s*=\s*[\'"][a-z0-9]{8,12}[\'"]', flags=0),
        "light_search": True,
    },
    "Helm Secret Value": {
        "regex": regex.compile(b'secret\s*:\s*[\'"][^\'"]+[\'"]', flags=regex.IGNORECASE),
        "light_search": True,
    },
    "Heroku API Key": [
        {
            "regex": regex.compile(b'[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}', flags=0),
            "light_search": True,
        },
        {
            "regex": regex.compile(b'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', flags=0),
            "light_search": True,
        },
        {
            "regex": regex.compile(b'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', flags=0),
            "light_search": True,
        },
        {
            "regex": regex.compile(b'[hH]eroku[\'"][0-9a-f]{32}[\'"]', flags=0),
            "light_search": True,
        },
    ],
    "HubSpot API Key": {
        "regex": regex.compile(b'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', flags=0),
        "light_search": True,
    },
    "IPv4 Address (Private)": {
        "regex": regex.compile(b'^(?:10\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)|172\.(?:1[6-9]|2\d|3[0-1])\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)|192\.168\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d))$', flags=0),
        "light_search": True,
    },
    "IPv4 Address (Public)": {
        "regex": regex.compile(b'^(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d))$', flags=0),
        "light_search": True,
    },
    "Instagram OAuth 2.0": {
        "regex": regex.compile(b'[0-9a-fA-F]{7}.[0-9a-fA-F]{32}', flags=0),
        "light_search": False,
    },
    "Intercom Access Token": {
        "regex": regex.compile(b'intercom(.{0,20})?token[\'"\s:=]+[a-zA-Z0-9-_]{20,}', flags=regex.IGNORECASE),
        "light_search": True,
    },
    "Internal Subdomain URL": {
        "regex": regex.compile(b'https?:\/\/[a-z0-9.-]+\.internal\.[a-z]{2,}', flags=0),
        "light_search": True,
    },
    "JDBC URL": {
        "regex": regex.compile(b'jdbc:\w+:\/\/[^\s\'"]+', flags=0),
        "light_search": True,
    },
    "JSON Web Token (JWT)": {
        "regex": regex.compile(b'eyJ((?:[a-zA-Z0-9_=]+\.){2}(?:[a-zA-Z0-9_\-\+\/=]*))', flags=0),
        "light_search": True,
    },
    "JSON Web Encryption (JWE) Token": {
        "regex": regex.compile(b"eyJ([a-zA-Z0-9\-_]+)\.([a-zA-Z0-9\-_]+)\.([a-zA-Z0-9\-_]+)\.([a-zA-Z0-9\-_]+)\.([a-zA-Z0-9\-_]+)", flags=0),
        "light_search": True,
    },
    "Jenkins Crumb Token": {
        "regex": regex.compile(b'Jenkins-Crumb:\s*[a-z0-9]{30,}', flags=0),
        "light_search": True,
    },
    "Keen IO Project ID": {
        "regex": regex.compile(b'projectId[\'"]?\s*:\s*[\'"][a-f0-9]{24}[\'"]', flags=0),
        "light_search": True,
    },
    "Keen IO Write Key": {
        "regex": regex.compile(b'writeKey[\'"]?\s*:\s*[\'"][a-zA-Z0-9]{64}[\'"]', flags=0),
        "light_search": True,
    },
    "Kubernetes Secret Name": {
        "regex": regex.compile(b'secretName:\s*[\'"]?[a-z0-9\-]+[\'"]?', flags=regex.IGNORECASE),
        "light_search": True,
    },
    "Linear API Key": {
        "regex": regex.compile(b'lin_api_[a-zA-Z0-9]{40}', flags=0),
        "light_search": True,
    },
    "LinkFinder": {
        "regex": regex.compile(b'(?:"|\')(((?:[a-zA-Z]{1,10}:\/\/|\/\/)[^"\'\/]{1,}\.[a-zA-Z]{2,}[^"\']{0,})|((?:\/|\.\.\/|\.\/)[^"\'><,;| *()(%%$^\/\\[\]][^"\'><,;|()]{1,})|([a-zA-Z0-9_\-\/]{1,}\/[a-zA-Z0-9_\-\/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|\']{0,}|))|([a-zA-Z0-9_\-\/]{1,}\/[a-zA-Z0-9_\-\/]{3,}(?:[\?|#][^"|\']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|\']{0,}|)))(?:"|\')', flags=0),
        "light_search": False,
    },
    "Localhost Reference": {
        "regex": regex.compile(b'localhost:[0-9]{2,5}', flags=0),
        "light_search": True,
    },
    "Loggly Token": {
        "regex": regex.compile(b'[a-z0-9]{30}-[a-z0-9]{10}', flags=0),
        "light_search": True,
    },
    "MAC Address": {
        "regex": regex.compile(b'(([0-9A-Fa-f]{2}[:]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{2}[-]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{4}[\.]){2}[0-9A-Fa-f]{4})$', flags=0),
        "light_search": True,
    },
    "MailChimp API Key": {
        "regex": regex.compile(b'[0-9a-f]{32}-us[0-9]{1,2}', flags=0),
        "light_search": True,
    },
    "Mailgun API Key": {
        "regex": regex.compile(b'key-[0-9a-zA-Z]{32}', flags=0),
        "light_search": True,
    },
    "Mailto": {
        "regex": regex.compile(b'(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+', flags=0),
        "light_search": True,
    },
    "Microsoft Teams Webhook": {
        "regex": regex.compile(b'https:\/\/[a-z]+\.webhook\.office\.com\/webhookb2\/[a-zA-Z0-9@\-]+\/.*', flags=0),
        "light_search": True,
    },
    "Mixpanel Token": {
        "regex": regex.compile(b'mixpanel(.{0,20})?token[\'"\s:=]+[a-z0-9]{32}', flags=regex.IGNORECASE),
        "light_search": True,
    },
    "MongoDB Connection URI": {
        "regex": regex.compile(b'mongodb(\+srv)?:\/\/[^\s\'"]+', flags=0),
        "light_search": True,
    },
    "MySQL URI": {
        "regex": regex.compile(b'mysql:\/\/[^\s\'"]+', flags=0),
        "light_search": True,
    },
    "Netlify Access Token": [
        {
            "regex": regex.compile(b'netlifyAuthToken\s*=\s*[\'"][a-z0-9]{40}[\'"]', flags=0),
            "light_search": True,
        },
        {
            "regex": regex.compile(b'nfp_[a-zA-Z0-9]{40}', flags=0),
            "light_search": True,
        },
    ],
    "New Relic Key": {
        "regex": regex.compile(b'NRII-[a-zA-Z0-9]{20,}', flags=0),
        "light_search": True,
    },
    "OAuth Client ID": {
        "regex": regex.compile(b'client_id[\'"\s:=]+[a-zA-Z0-9\-_.~]{10,100}', flags=0),
        "light_search": False,
    },
    "OAuth Client Secret": {
        "regex": regex.compile(b'client_secret[\'"\s:=]+[a-zA-Z0-9\-_.~]{10,100}', flags=0),
        "light_search": True,
    },
    "OpenAI Service ID": {
        "regex": regex.compile(b'^[A-Za-z0-9]+(-*[A-Za-z0-9]+)*$', flags=0),
        "light_search": True,
    },
    "OpenAI Service Key": {
        "regex": regex.compile(b'sk-{SERVICE ID}-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}', flags=0),
        "light_search": True,
    },
    "OpenAI User API Key": {
        "regex": regex.compile(b'sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}', flags=0),
        "light_search": True,
    },
    "OpenAI User Project Key": {
        "regex": regex.compile(b'sk-proj-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}', flags=0),
        "light_search": True,
    },
    "PEM File Content": {
        "regex": regex.compile(b'-----BEGIN CERTIFICATE-----', flags=0),
        "light_search": True,
    },
    "PGP Private Key Block": {
        "regex": regex.compile(b'-----BEGIN PGP PRIVATE KEY BLOCK-----', flags=0),
        "light_search": True,
    },
    "Password Assignment": {
        "regex": regex.compile(b'(password|pwd|pass)[\'"\s:=]+[^\s\'"]{4,100}', flags=regex.IGNORECASE),
        "light_search": False,
    },
    "Password in URL": {
        "regex": regex.compile(b'[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["\'\s]', flags=0),
        "light_search": True,
    },
    "PayPal Braintree Access Token": [
        {
            "regex": regex.compile(b'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}', flags=0),
            "light_search": True,
        },
        {
            "regex": regex.compile(b'access_token,production\$[0-9a-z]{16}\$[0-9a-f]{32}', flags=0),
            "light_search": True,
        },
    ],
    "Picatic API Key": {
        "regex": regex.compile(b'sk_live_[0-9a-z]{32}', flags=0),
        "light_search": True,
    },
    "Plaid Client Secret": {
        "regex": regex.compile(b'plaid(.{0,20})?(client)?secret[\'"\s:=]+[a-z0-9-_]{30,}', flags=0),
        "light_search": True,
    },
    "PostgreSQL URI": {
        "regex": regex.compile(b'postgres(?:ql)?:\/\/[^\s\'"]+', flags=0),
        "light_search": True,
    },
    "Preprod URLs": {
        "regex": regex.compile(b'https:\/\/preprod\.[a-z0-9-]+\.[a-z]{2,}', flags=0),
        "light_search": True,
    },
    "RSA Private Key": {
        "regex": regex.compile(b'-----BEGIN RSA PRIVATE KEY-----', flags=0),
        "light_search": True,
    },
    "Redis URI": {
        "regex": regex.compile(b'redis:\/\/[^\s\'"]+', flags=0),
        "light_search": True,
    },
    "Riot Games API Key": {
        "regex": regex.compile(b'RGAPI-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', flags=0),
        "light_search": True,
    },
    "Rollbar Access Token": {
        "regex": regex.compile(b'access_token[\'"]?\s*:\s*[\'"][a-z0-9]{32}[\'"]', flags=0),
        "light_search": True,
    },
    "SSH DSA Private Key": {
        "regex": regex.compile(b'-----BEGIN DSA PRIVATE KEY-----', flags=0),
        "light_search": True,
    },
    "SSH EC Private Key": {
        "regex": regex.compile(b'-----BEGIN EC PRIVATE KEY-----', flags=0),
        "light_search": True,
    },
    "Secret in Variable": {
        "regex": regex.compile(b'(secret|token)[\'"\s:=]+[a-zA-Z0-9\-_.]{8,100}', flags=regex.IGNORECASE),
        "light_search": False,
    },
    "Segment API Key": {
        "regex": regex.compile(b'segment(.{0,20})?key[\'"\s:=]+[a-zA-Z0-9]{10,}', flags=regex.IGNORECASE),
        "light_search": True,
    },
    "SendGrid API Key": {
        "regex": regex.compile(b'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}', flags=0),
        "light_search": True,
    },
    "Sentry DSN": {
        "regex": regex.compile(b'https:\/\/[a-zA-Z0-9]+@[a-z]+\.ingest\.sentry\.io\/\d+', flags=0),
        "light_search": True,
    },
    "Session ID": {
        "regex": regex.compile(b'(sessionid|session_id)[\'"\s:=]+[a-zA-Z0-9]{10,}', flags=regex.IGNORECASE),
        "light_search": True,
    },
    "Shopify Admin API AccessToken": {
        "regex": regex.compile(b'shpat_[0-9a-f]{32}', flags=0),
        "light_search": True,
    },
    "Shopify Custom App API AccessToken": {
        "regex": regex.compile(b'shpca_[0-9a-f]{32}', flags=0),
        "light_search": True,
    },
    "Slack OAuth v2 Configuration Token": {
        "regex": regex.compile(b'xoxe.xoxp-1-[0-9a-zA-Z]{166}', flags=0),
        "light_search": True,
    },
    "Slack OAuth v2 Refresh Token": {
        "regex": regex.compile(b'xoxe-1-[0-9a-zA-Z]{147}', flags=0),
        "light_search": True,
    },
    "Slack API Token": {
        "regex": regex.compile(b'xox[p|b|o|a|e|r]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}', flags=0),
        "light_search": True,
    },
    "Slack Oauth V2 Access Token": {
        "regex": regex.compile(b'xoxb-[0-9a-zA-Z]{10,25}-[0-9a-zA-Z]{10,25}-[0-9a-zA-Z]{10,40}', flags=0),
        "light_search": True,
    },
    "Slack Token": {
        "regex": regex.compile(b'(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})', flags=0),
        "light_search": True,
    },
    "Slack_Webhook": [
        {
            "regex": regex.compile(b'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}', flags=0),
            "light_search": True,
        },
        {
            "regex": regex.compile(b'T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}', flags=0),
            "light_search": True,
        }
    ],
    "Snyk Token": {
        "regex": regex.compile(b'snyk_token\s*=\s*[a-f0-9\-]{36}', flags=0),
        "light_search": True,
    },
    "Square Access Token": {
        "regex": regex.compile(b'sq0atp-[0-9A-Za-z\-_]{22}', flags=0),
        "light_search": True,
    },
    "Square OAuth Secret": {
        "regex": regex.compile(b'sq0csp-[0-9A-Za-z\-_]{43}', flags=0),
        "light_search": True,
    },
    "Stripe Secret Key": {
        "regex": regex.compile(b'sk_live_[0-9a-zA-Z]{24}', flags=0),
        "light_search": True,
    },
    "Stripe API Key": {
        "regex": regex.compile(b'sk_live_[0-9a-zA-Z]{24}', flags=0),
        "light_search": True,
    },
    "Stripe Publishable Key": {
        "regex": regex.compile(b'pk_(?:live|test)_[a-zA-Z0-9]{24}', flags=0),
        "light_search": True,
    },
    "Stripe Restricted API Key": {
        "regex": regex.compile(b'rk_live_[0-9a-zA-Z]{24}', flags=0),
        "light_search": True,
    },
    "Stripe Test API Key": {
        "regex": regex.compile(b'sk_test_[0-9a-zA-Z]{24}', flags=0),
        "light_search": True,
    },
    "Stripe Webhook Secret": {
        "regex": regex.compile(b'whsec_[0-9a-zA-Z]{48}', flags=0),
        "light_search": True,
    },
    "Supabase DB Key": {
        "regex": regex.compile(b'supabase\.co\/[a-z0-9]{15,}', flags=0),
        "light_search": True,
    },
    "Telegram Bot Token": {
        "regex": regex.compile(b'\d{9}:[a-zA-Z0-9_-]{35}', flags=0),
        "light_search": True,
    },
    "Travis CI Token": {
        "regex": regex.compile(b'travis(.{0,20})?token[\'"\s:=]+[a-z0-9]{30,}', flags=regex.IGNORECASE),
        "light_search": True,
    },
    "Twilio API Key": {
        "regex": regex.compile(b'SK[0-9a-fA-F]{32}', flags=0),
        "light_search": True,
    },
    "Twilio Access Token": {
        "regex": regex.compile(b'55[0-9a-fA-F]{32}', flags=0),
        "light_search": False,
    },
    "Twitch API Key": {
        "regex": regex.compile(b'twitch(.{0,20})?key[\'"\s:=]+[a-zA-Z0-9]{20,}', flags=regex.IGNORECASE),
        "light_search": True,
    },
    "Twitter Access Token": {
        "regex": regex.compile(b'[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}', flags=0),
        "light_search": False,
    },
    "Twitter ClientID": {
        "regex": regex.compile(b'[t|T][w|W][i|I][t|T][t|T][e|E][r|R](.{0,20})?[\'"][0-9a-z]{18,25}', flags=0),
        "light_search": True,
    },
    "Twitter OAuth": {
        "regex": regex.compile(b'[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[\'|"][0-9a-zA-Z]{35,44}[\'|"]', flags=0),
        "light_search": True,
    },
    "Twitter Secret Key": {
        "regex": regex.compile(b'[t|T][w|W][i|I][t|T][t|T][e|E][r|R](.{0,20})?[\'"][0-9a-z]{35,44}', flags=0),
        "light_search": True,
    },
    "Vault Token": {
        "regex": regex.compile(b's\.[a-zA-Z0-9]{8,}', flags=0),
        "light_search": False,
    },
    "WakaTime API Key": {
        "regex": regex.compile(b'waka_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', flags=0),
        "light_search": True,
    }
}

CHUNK_SIZE = 1024 * 1024  # 1 MB chunks

def regex_match(name, patterns, content, filepath, light_search):
    found_matches = []
    for p in patterns:
        # Skip patterns not marked for light_search if light_search is enabled
        if light_search and not p["light_search"]:
            continue
        try:
            start = 0
            content_len = len(content)
            # Process the content in chunks to avoid memory issues
            while start < content_len:
                chunk = content[start:start+CHUNK_SIZE]
                try:
                    # Find all matches for the regex in the current chunk
                    for match in p["regex"].finditer(chunk):
                        try:
                            # Try to decode the match to UTF-8
                            found_matches.append({
                                "pattern_name": name,
                                "match": match.group().decode('utf-8'),
                                "file": filepath
                            })
                        except UnicodeDecodeError:
                            # If decoding fails, note it as non-decodable
                            found_matches.append({
                                "pattern_name": name,
                                "match": f"{match.group()} (Non Decodificabile)",
                                "file": filepath
                            })
                except regex.TimeoutError:
                    # Handle regex timeout for large or complex patterns
                    print(f"Regex timed out in file {filepath}, chunk {start}-{start+CHUNK_SIZE}")
                start += CHUNK_SIZE
        except Exception as e:
            # Catch-all for unexpected errors in pattern processing
            print(f"Error processing pattern {name} in {filepath}: {e}")
    return found_matches

def regex_scan_file(filepath_tuple, light_search=False):
    rootpath, filepath = filepath_tuple
    print(f"{filepath}")
    all_matches = []

    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                # For each regex pattern, search for matches in the chunk
                for name, pattern in SECRETS_REGEX.items():
                    if isinstance(pattern, list):
                        all_matches.extend(regex_match(name, pattern, chunk, filepath, light_search))
                    else:
                        all_matches.extend(regex_match(name, [pattern], chunk, filepath, light_search))
    except (FileNotFoundError, IOError) as e:
        # Handle file access errors
        print(f"Error opening {filepath}: {e}", file=sys.stderr)

    return all_matches

def gather_files(target_path):
    files = []
    if os.path.isdir(target_path):
        # Recursively collect all files in the directory
        for dirpath, _, filenames in os.walk(target_path):
            for filename in filenames:
                files.append((target_path, os.path.join(dirpath, filename)))
    else:
        # Single file case
        files.append((target_path, target_path))
    return files

def write_regex_results_csv(all_matches, output_file):
    if not all_matches:
        return
    
    # Sort matches for consistent output
    sorted_matches = sorted(all_matches, key=lambda x: (x["pattern_name"], x["file"], x["match"]))
    
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Regex", "Match", "File"])
        writer.writeheader()
        for match in sorted_matches:
            writer.writerow({
                "Regex": match["pattern_name"],
                "Match": match["match"],
                "File": match["file"]
            })

def print_regex_results_console(all_matches, root_folder):
    if not all_matches:
        print(colored("No matches found.", "yellow"))
        return
    
    # Sort matches for display
    sorted_matches = sorted(all_matches, key=lambda x: (x["pattern_name"], x["file"], x["match"]))
    
    # Prepare summaries for files and patterns
    file_summary = defaultdict(int)
    pattern_summary = defaultdict(lambda: {"matches": 0, "files": set()})
    
    # Table for all matches
    matches_table = []
    for match in sorted_matches:
        matches_table.append([
            colored(match['pattern_name'], 'green'),
            colored(match['file'], 'blue'),
            colored(match['match'], 'red')
        ])
        file_summary[match["file"]] += 1
        pattern_summary[match["pattern_name"]]["matches"] += 1
        pattern_summary[match["pattern_name"]]["files"].add(match["file"])
    
    # File summary table
    file_table = [[colored(file.replace(root_folder, "..."), "blue"), colored(count, "yellow")] for file, count in file_summary.items()]
    print("\n" + colored("=== FILE SUMMARY ===", "magenta", attrs=["bold"]))
    print(tabulate(file_table, headers=[colored("File", "red"), colored("Matches", "red")], tablefmt='fancy_grid', colalign=('left', 'center')))
    
    # Pattern summary table
    pattern_table = [[colored(pattern, "green"), colored(info['matches'], "yellow"), colored(len(info['files']), "cyan")]
                     for pattern, info in pattern_summary.items()]
    print("\n" + colored("=== PATTERN SUMMARY ===", "magenta", attrs=["bold"]))
    print(tabulate(pattern_table, headers=[colored("Pattern", "red"), colored("Matches", "red"), colored("Files", "red")], tablefmt='fancy_grid', colalign=('left', 'center', 'center')))

def full_secrets_search(user_input):
    target_path = user_input
    # Prompt user until a valid path is provided
    while not os.path.exists(target_path):
        target_path = input("Insert a valid path (file or folder): ")

    all_files = gather_files(target_path)
    max_workers = min(os.cpu_count(), len(all_files))
    print(f"Full search on '{target_path}' ({len(all_files)} files) with {max_workers} processes...")

    all_matches = []
    # Use multiprocessing for faster scanning
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        for file_matches in executor.map(regex_scan_file, all_files, [False]*len(all_files)):
            all_matches.extend(file_matches)

    now = current_date()
    results_folder = os.path.join("results", "advanced_search")
    os.makedirs(results_folder, exist_ok=True)

    results_filepath = os.path.join(results_folder, f"{now}_full_secrets.csv")
    write_regex_results_csv(all_matches, results_filepath)
    print("Full search results saved to " + colored(results_filepath, "red"))

    print_regex_results_console(all_matches, user_input)

def light_secrets_search(user_input):
    target_path = user_input
    # Prompt user until a valid path is provided
    while not os.path.exists(target_path):
        target_path = input("Insert a valid path (file or folder): ")

    all_files = gather_files(target_path)
    max_workers = min(os.cpu_count(), len(all_files))
    print(f"Light search on '{target_path}' ({len(all_files)} files) with {max_workers} processes...")

    all_matches = []
    # Use multiprocessing for faster scanning (light mode)
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        for file_matches in executor.map(regex_scan_file, all_files, [True]*len(all_files)):
            all_matches.extend(file_matches)

    now = current_date()
    results_folder = os.path.join("results", "advanced_search")
    os.makedirs(results_folder, exist_ok=True)

    results_filepath = os.path.join(results_folder, f"{now}_light_secrets.csv")
    write_regex_results_csv(all_matches, results_filepath)
    print("Light search results saved to " + colored(results_filepath, "red"))

    print_regex_results_console(all_matches, user_input)


def bytes_search_in_file(filepath_tuple: tuple, search_bytes_lower: bytes) -> list:
    rootpath, filepath = filepath_tuple
    matches = []

    try:
        with open(filepath, "rb") as f:
            content = f.read()
        
        content_lower = content.lower()
        search_len = len(search_bytes_lower)
        
        # We need to find the index of the match in the lowercase content
        # and then extract the original string from the original content.
        index = content_lower.find(search_bytes_lower)
        while index != -1:
            found_bytes = content[index : index + search_len]
            
            # Check if the found bytes are decodable as UTF-8
            try:
                found_string = found_bytes.decode('utf-8')
                matches.append((filepath, found_string))
            except UnicodeDecodeError:
                # If it's not a valid UTF-8 string, we'll represent it as a hex string
                matches.append((filepath, f"0x{found_bytes.hex()}"))

            # Continue searching for the next occurrence
            index = content_lower.find(search_bytes_lower, index + 1)
            
    except (FileNotFoundError, IOError) as e:
        print(f"Error opening {filepath}: {e}", file=sys.stderr)
        
    return matches

def write_string_results_csv(all_matches, search_string, output_file):
    """
    Writes the search results to a CSV file.
    """
    if not all_matches:
        print("No matches found.")
        return
    
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Search String", "Found String", "File Path"])
        writer.writeheader()
        for filepath, found_string in all_matches:
            writer.writerow({
                "Search String": search_string,
                "Found String": found_string,
                "File Path": filepath
            })
            
    print("Advanced search results for "+colored(search_string, "yellow")+" saved to "+colored(output_file, "red"))

def input_string_from_user(prompt_string, lowercase):
    while True:
        search_string = input(prompt_string)
        if search_string.strip():
            break

    if search_string.startswith('0x'):
        bytes_string = bytes.fromhex(search_string[2:])
    else:
        bytes_string = search_string.encode('utf-8')

    if lowercase:
        return search_string, bytes_string.lower()
    else:
        return search_string, bytes_string

def search_string_in_files(user_input):
    while not os.path.exists(user_input):
        user_input = input("Insert a valid path (file or folder):\n")

    search_string, bytes_string = input_string_from_user("Insert the string or the byte sequence (0x<hex>) to be searched in all the files:\n", lowercase=True)

    all_files = gather_files(user_input)
    max_workers = min(os.cpu_count(), len(all_files))
    print(f"Advanced search of the input string on '{user_input}' ({len(all_files)} files) with {max_workers} processes...")

    all_matches = []
    # Use multiprocessing for faster scanning (light mode)
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        for file_matches in executor.map(bytes_search_in_file, all_files, [bytes_string]*len(all_files)):
            all_matches.extend(file_matches)

    now = current_date()
    results_folder = os.path.join("results", "advanced_search")
    os.makedirs(results_folder, exist_ok=True)

    results_filepath = os.path.join(results_folder, f"{now}_advanced_search.csv")
    write_string_results_csv(all_matches, search_string, results_filepath)

def bytes_replacement_in_file(filepath_tuple: tuple, search_bytes: bytes, replace_bytes: bytes) -> list:
    rootpath, filepath = filepath_tuple
    print(filepath, end="", flush=True)
    matches = []

    try:
        with open(filepath, "rb") as f:
            content = f.read()
        
        count = content.count(search_bytes)
        
        if count > 0:
            content = content.replace(search_bytes, replace_bytes)

            with open(filepath, "wb") as f:
                f.write(content)
                
            print(" > "+colored(count, "green")+" replacements done")

        else:
            print(" > "+colored(count, "red")+" occurrences found")

    except (FileNotFoundError, IOError) as e:
        print(f"Error opening {filepath}: {e}", file=sys.stderr)
        
    return matches


def replace_string_in_files(user_input):
    while not os.path.exists(user_input):
        user_input = input("Insert a valid path (file or folder):\n")

    search_string, bytes_search_string = input_string_from_user("Insert the string or the byte sequence (0x<hex>) to be searched in all the files:\n", lowercase=False)
    replace_string, bytes_replace_string = input_string_from_user("Insert the string or the byte sequence (0x<hex>) that will replace the previous one in all the files:\n", lowercase=False)

    all_files = gather_files(user_input)
    max_workers = min(os.cpu_count(), len(all_files))

    print("Searching for: "+colored(search_string, "yellow"))
    print("Replacing with: "+colored(replace_string, "yellow"))

    print(f"Advanced replacement of the input string on '{user_input}' ({len(all_files)} files) with {max_workers} processes...")

    all_matches = []
    # Use multiprocessing for faster scanning (light mode)
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        for file_matches in executor.map(bytes_replacement_in_file, all_files, [bytes_search_string]*len(all_files), [bytes_replace_string]*len(all_files)):
            all_matches.extend(file_matches)
