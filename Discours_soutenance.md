# Discours de soutenance (environ 10 minutes)

À adapter : nom, encadrant, établissement. Ne rien affirmer qui ne soit pas dans le code.

---

Monsieur / Madame le président, membres du jury,

Ce PFE porte sur un **prototype** de chaîne DevSecOps : détection d’anomalies comportementales sur un cluster Kubernetes de laboratoire, puis isolation réseau automatique.

Le constat est simple. Falco voit beaucoup d’événements. Tout n’est pas une attaque. Un administrateur qui lit un fichier sensible en journée n’est pas le même signal qu’un compte de service qui lance un shell à 2 h du matin vers un domaine IOC.

**Objectif réalisé :** relier Falco, un moteur d’IA hybride, et une politique Cilium, sur Kind, provisionné par Terraform.

**Ce qui tourne vraiment.** Terraform crée un cluster Kind à deux nœuds, CNI par défaut désactivé, Cilium 1.16, Falco en eBPF moderne, Falcosidekick en webhook uniquement — **sans UI**. Un nginx dans `demo-app` est la cible. Le collector Flask écoute `:5002`, expose des métriques Prometheus sur `:8000`.

L’IA a deux couches. Un Random Forest global, arbres peu profonds pour ne pas recopier Falco. Un UBA par UID : histogramme horaire Africa/Tunis, IsolationForest si assez d’événements. Le score combiné est 35 % RF + 65 % UBA, avec des règles d’arbitrage dans `engine.py`. **La quarantaine ne part que si le score est ≥ 70.** Dans ce cas on pose `quarantine=true`, Cilium coupe ingress et egress, on scale un replica sain, on tente Jira et Gmail **s’ils sont configurés**. Le process n’est pas tué : c’est voulu pour la forensique.

**Ce que ce prototype n’est pas.** Pas de Maven, pas d’image Docker custom, pas de CI/CD, pas de cloud managé. Kind utilise Docker comme runtime. L’inbound Falco existe en règle, **n’est pas rejoué** en démo. Après quarantaine, rien n’est automatique : pas de rebuild, pas de rotation de secrets.

La validation : dataset synthétique enrichi, `run_train.py`, table `demo_decision_table.py`, et **un** scénario sûr `scripts/demo_attaque.sh` aligné sur les règles déployées.

Je vous propose maintenant la démonstration live, puis je répondrai à vos questions.
