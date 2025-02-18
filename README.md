1 2 3

# Tema 1 - Alexandra Bulgaru 331CD

### 1. Procesul de comutare:
- Gestioneaza primirea, analiza si transmiterea cadrelor Ethernet prin retea. Cand un cadru este primit pe o interfata, `parse_ethernet_header` extrage informatiile despre adresele MAC de destinatie si sursa, tipul Ethernet si ID-ul VLAN-ului.
- Tabela MAC este actualizata cu adresa MAC sursa si interfata de unde a fost primit cadrul.
- Transmiterea cadrelor se realizeaza diferit in functie de tipul lor. _Cadrele broadcast si multicast_ sunt inundate catre toate interfetele relevante, excluzand interfata de intrare si porturile care sunt BLOCKING pentru a preveni buclele. _Cadrele unicast:_ daca adresa de destinatie este in tabela MAC, cadrul este trimis direct catre interfata corespunzatoare. Daca nu, este inuntat catre porturile compatibile. `prepare_frame_for_sending` pregateste cadrele in functie de configuratia VLAN a porturilor de iesire.

### 2. VLAN:
- Se adauga si se elimina tag-uri VLAN din cadrele Ethernet, permitand segmentarea traficului in retea. `parse_ethernet_header` detecteaza prezenta unui tag VLAN si ii extrage ID-ul corespunzator. `add_vlan_tag` si `remove_vlan_tag` gestioneaza modificarea cadrului Ethernet pentru a include sau exclude informatiile VLAN, in functie de configuratia porturilor. Astfel se asigura ca traficul este etichetat corect cand trece prin porturile trunk.
- `read_config` citeste din fisierele de configurare datele despre switch-uri, unde fiecare port poate fi setat ca _trunk_ sau _access_ `prepare_frame_for_sending` pregateste cadrele in functie de tipul portului de iesire, adaugand tag-uri VLAN pentru porturile trunk si eliminandu-le pentru cele de acces. Astfel se permite izolarea traficului intre diferite segmente de retea.

### 3. STP:
- Previne buclele in reteaua de comutare. BPDU-urile comunica informatii despre topologia retelei intre switch-uri. `send_bpdu` construieste si trimite BPDU-uri periodice folosindu-se de `send_bdpu_every_sec` care actualizeaza constant informatiile despre bridge root si costurile traseelor. Astfel, switch-urile determina care porturi trebuie activate sau blocate pentru a evita buclele.
- Cand se primeste un BPDU, `parse_bpdu` extrage detaliile competente, iar switch-ul le compara cu starea proprie pentru a decide daca trebuie facute modificari. Un bridge cu un ID mai mic duce la actualizarea starii switch-ului pentru a reflecta noua topologie, ducand la modificarea starilor porturilor. `PortInfo` gestioneaza starile de **BLOCKING** si **LISTENING**, precum si daca sunt **designated** sau nu.
