# 🛡️ CloudSecVision - Scan des Buckets S3 Publics avec boto3 (AWS)

Outil de détection des buckets S3 publics pour assurer la sécurité de votre infrastructure AWS.

## 📋 Table des matières

- [🎯 Introduction](#-introduction)
- [⚙️ Pré-requis](#️-pré-requis)
- [🚀 Installation](#-installation)
- [🔧 Configuration AWS](#-configuration-aws)
- [📝 Utilisation](#-utilisation)
- [🔍 Fonctionnalités](#-fonctionnalités)
- [📊 Structure du projet](#-structure-du-projet)
- [🔒 Bonnes pratiques](#-bonnes-pratiques)
- [🛡️ Sécurité](#️-sécurité)

## 🎯 Introduction

Ce projet permet de détecter automatiquement les buckets S3 publics sur un compte AWS en utilisant la bibliothèque Python boto3. L'objectif principal est d'identifier les buckets configurés en accès public afin d'assurer la sécurité des données et de respecter les bonnes pratiques de sécurité cloud.

## ⚙️ Pré-requis

- Compte AWS avec accès IAM approprié
- Python 3.6 ou supérieur
- Clés d'accès AWS (Access Key ID et Secret Access Key)

## 🚀 Installation

### 1. Cloner le projet
```bash
git clone <votre-repo>
cd cloudsecvision
```

### 2. Installer les dépendances
```bash
pip install boto3
```

## 🔧 Configuration AWS

### Création des clés d'accès

1. Connectez-vous à la console AWS
2. Accédez à **IAM > Utilisateurs**
3. Sélectionnez votre utilisateur ou créez-en un nouveau
4. Dans l'onglet **Security credentials**, cliquez sur **Create access key**
5. Notez l'Access Key ID et le Secret Access Key générés

⚠️ **Important** : Ne partagez jamais ces clés publiquement et stockez-les de manière sécurisée.

### Configuration avec AWS CLI
```bash
aws configure
```

Entrez les informations demandées :
- **AWS Access Key ID** : votre clé d'accès
- **AWS Secret Access Key** : votre clé secrète
- **Default region name** : eu-west-3 (Paris)
- **Default output format** : json

## 📝 Utilisation

### Lancement du script
```bash
python3 src/s3_scanner.py
```

### Exemple de sortie
```
Script started
🌐 Buckets detected : 2
✅ Private bucket : youcef-s3-private-bucket-01
🚨 Public bucket found : youcef-s3-test-bucket-01
```

## 🔍 Fonctionnalités

Le script propose les fonctionnalités suivantes :

- **Listage des buckets** : Récupère automatiquement tous les buckets S3 du compte
- **Détection des accès publics** : Analyse les ACLs pour identifier les buckets publics
- **Rapport détaillé** : Affiche un résumé clair avec des icônes pour une lecture rapide
- **Gestion d'erreurs** : Capture et affiche les erreurs d'accès aux buckets

### Code principal
```python
import boto3

def list_buckets():
    """Récupère la liste de tous les buckets S3"""
    s3 = boto3.client('s3')
    response = s3.list_buckets()
    return [bucket['Name'] for bucket in response['Buckets']]

def check_bucket_public(bucket_name):
    """Vérifie si un bucket est accessible publiquement"""
    s3 = boto3.client('s3')
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl['Grants']:
            if 'AllUsers' in grant['Grantee'].get('URI', ''):
                return True
        return False
    except Exception as e:
        print(f"Error checking {bucket_name}: {e}")
        return False

def main():
    """Fonction principale"""
    print("Script started")
    buckets = list_buckets()
    print(f"🌐 Buckets detected : {len(buckets)}")
    
    for bucket in buckets:
        if check_bucket_public(bucket):
            print(f"🚨 Public bucket found : {bucket}")
        else:
            print(f"✅ Private bucket : {bucket}")

if __name__ == "__main__":
    main()
```

## 📊 Structure du projet

```
cloudsecvision/
├── src/
│   └── s3_scanner.py
├── README.md
├── requirements.txt
├── aws/
├── config/
├── data/
├── docs/
└── test/
```

## 🔒 Bonnes pratiques

- **Sécurité des clés** : Ne jamais exposer vos clés d'accès dans le code ou les repositories
- **Principe du moindre privilège** : Utilisez des droits IAM minimaux nécessaires
- **Éviter les accès publics** : N'autorisez les accès publics que lorsque c'est strictement nécessaire
- **Rotation des clés** : Automatisez la rotation régulière des clés d'accès
- **Monitoring** : Surveillez la sécurité avec AWS Config, Trusted Advisor, et CloudTrail

### Permissions IAM minimales requises
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketAcl"
            ],
            "Resource": "*"
        }
    ]
}
```

## 🛡️ Sécurité

Ce script effectue uniquement des opérations de lecture et ne modifie aucune configuration de vos buckets S3. Il est conçu pour être un outil d'audit non intrusif.

---

**Développé par Youcef** - Projet M1 Sécurité Cloud & AWS
