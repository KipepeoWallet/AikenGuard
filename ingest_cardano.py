#!/usr/bin/env python3
"""
AikenGuard RAG — Script d'ingestion Cardano
Indexe toutes les sources Cardano dans ChromaDB

Usage: python3 ingest_cardano.py
"""

import os
import sys
import json
import subprocess
from pathlib import Path
import chromadb
from sentence_transformers import SentenceTransformer

DB_PATH    = "/home/ubuntu/cardano-rag"
MODEL_NAME = "all-MiniLM-L6-v2"

SOURCES = [
    ("git", "https://github.com/vacuumlabs/cardano-ctf",     "vacuumlabs-ctf"),
    ("git", "https://github.com/vacuumlabs/audits",          "vacuumlabs-audits"),
    ("git", "https://github.com/aiken-lang/stdlib",          "aiken-stdlib"),
    ("git", "https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform", "aikido"),
]

WEB_PAGES = [
    ("https://aiken-lang.org/language-tour",           "aiken-language-tour"),
    ("https://cips.cardano.org",                       "cardano-cips"),
    ("https://docs.cardano.org",                       "cardano-docs"),
]


def clone_repo(url, name, tmp_dir="/tmp/rag"):
    path = f"{tmp_dir}/{name}"
    if Path(path).exists():
        print(f"  Deja present: {name}")
        subprocess.run(["git", "-C", path, "pull", "--quiet"], capture_output=True)
        return path
    print(f"  Clonage: {name}...")
    subprocess.run(["git", "clone", "--depth=1", "--quiet", url, path], capture_output=True)
    return path


def extract_texts_from_repo(repo_path, extensions=[".ak", ".md", ".txt"]):
    texts = []
    for ext in extensions:
        for f in Path(repo_path).rglob(f"*{ext}"):
            if "build" in str(f) or ".git" in str(f):
                continue
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                if len(content.strip()) > 50:
                    texts.append({
                        "content": content,
                        "source":  str(f),
                        "name":    f.name,
                    })
            except:
                pass
    return texts


def chunk_text(text, chunk_size=400, overlap=50):
    words = text.split()
    chunks = []
    i = 0
    while i < len(words):
        chunk = " ".join(words[i:i+chunk_size])
        chunks.append(chunk)
        i += chunk_size - overlap
    return chunks


def main():
    print("\nAikenGuard RAG — Ingestion Cardano")
    print("=" * 50)

    # Créer les dossiers
    Path("/tmp/rag").mkdir(exist_ok=True)
    Path(DB_PATH).mkdir(exist_ok=True)

    # Initialiser ChromaDB
    print("\nInitialisation ChromaDB...")
    client = chromadb.PersistentClient(path=DB_PATH)
    collection = client.get_or_create_collection(
        name="cardano_knowledge",
        metadata={"hnsw:space": "cosine"}
    )

    # Charger le modèle d'embedding
    print(f"Chargement du modele {MODEL_NAME}...")
    model = SentenceTransformer(MODEL_NAME)

    total_chunks = 0

    # Ingerer les repos Git
    print("\nIngestion des repos Git...")
    for source_type, url, name in SOURCES:
        print(f"\n  {name}:")
        repo_path = clone_repo(url, name)
        texts = extract_texts_from_repo(repo_path)
        print(f"  {len(texts)} fichiers trouves")

        for doc in texts:
            chunks = chunk_text(doc["content"])
            for i, chunk in enumerate(chunks):
                if len(chunk.strip()) < 30:
                    continue
                doc_id = f"{name}_{doc['name']}_{i}"
                try:
                    embedding = model.encode(chunk).tolist()
                    collection.upsert(
                        ids=[doc_id],
                        embeddings=[embedding],
                        documents=[chunk],
                        metadatas=[{
                            "source": doc["source"],
                            "name":   doc["name"],
                            "repo":   name,
                        }]
                    )
                    total_chunks += 1
                except:
                    pass

        print(f"  Indexe!")

    print(f"\nTotal chunks indexes: {total_chunks}")
    print(f"Base de donnees: {DB_PATH}")
    print("\nIngestion terminee!")

    # Test rapide
    print("\nTest de recherche...")
    test_query = "double satisfaction vulnerability Cardano"
    embedding = model.encode(test_query).tolist()
    results = collection.query(
        query_embeddings=[embedding],
        n_results=3
    )
    print(f"Requete: '{test_query}'")
    for i, doc in enumerate(results["documents"][0]):
        src = results["metadatas"][0][i]["source"]
        print(f"  Resultat {i+1}: {src[:60]}...")
        print(f"  {doc[:100]}...")
    print("\nRAG pret!")


if __name__ == "__main__":
    main()
