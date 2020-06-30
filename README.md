First of all, thanks to my colleague xl58. My work maybe be delayed without him. Besides thanks to the author of dpkg library, they provide a straight way to parse various network protocols using python.

This repository is dedicated to transfer traffic in pcap and pcapng to flow. The results of flows is store in json file. It's a pre-work of Traffic Classification. After processing network traffic, you can extract other features of traffic from json files. Based on the features you have extracted, you can feed the features in Machine Learning (ML) Algorithms. This repository won't provide ML Algorithms, the main work is to transfer packet in pcap and pcapng to flow.

Environment and Installation
The libpcap, dpkt and pypcap libraty is needed This repository. When you using the program, please use python3.

Libpcap installation
sudo apt-get install build-essential libpcap-dev

Dpkt installation
pip3 install dpkt

Pypcap installation
pip3 install pypcap

After preparation, the program can directly use.

Runnning
python3 pcap2json.py -i /yourpath1/input -o /yourpath2/output -n class -s -m

The directory input contains some subdirectories. These subdirectories contains the pcap and pcapng traffic. Each subdirectory represent a categary of the network traffic you want to classify. In other words, the amount of these subdirectories is equal to the categories of your network traffic.
The directory output contains json files, which cantain the flow results. The amount of json files is equal to the categories of your network traffic.
The option -n means the name of output files, e.g class1.json class2.json class3.json.
The option -s means combine packets to flow in bidirection way. The flow is bi-flow after using this option.
The option -m means more accuracy features in json flow, including 5-tuple, IP layer field, Tcp layer field and payload in packet. If option -m is not used, the coarse-grain result will be obtained. However it maybe give you more freedom to parsing the data by yourself. This option may be desperated in the future.

New feature comparing with xl58
1. Firstly, the udp traffic is able to process.
2. Secondly, the timestamp of each packet in the flow has been extracted. The timestamp of packet is delta comparing with the first packet in flow.
3. Thirdly, the 5-tuples have included in the json files, when option -m used.
4. IPv6 has been supoorted.
5. There are two 2-layer type can parsing using dpkt,ethernet and raw packet which has no 2-layer. But the raw packet parsing only supoort IPv4.
6. The retransmittion

Some modification
1.There is no padding in payload. 
2.More comments

Useful tool
pkt2flow https://github.com/caesar0301/pkt2flow. When you want to process traffic in pcap or pcapng file which cantain many flows to single-flow pcaps or pcapngs, this tool may be helpful.

Future work
1. non-tcp and non-udp traffic will be processed in the future. 
