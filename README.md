# TFM_MASTER_MUIT
Developed code for Thessis

All this code was created with academic purpose to develop the Master's Thessis.


This Master’s Thesis is about developing and implementing a monitoring framework for the emerging SDN networks at the application layer. To achieve the main goal, many different manufacturers have bet about monitoring, but this Thesis is based in OpenFlow software, which is open source. By default, the monitoring layer it is not developed, fact that limit the monitoring and statistics types that we can get. However OpenFlow protocol, allows obtaining statistics (bytes and packets) per flows defined by fields at the Ethernet, IP and TCP levels.  The goal proposed in this Thesis is to take advantage of this existing monitoring system and build on it an abstraction layer that allows us to obtain statistics (bytes and packets per stream) related to Web browsing, focusing on HTTP, SSL and DNS. The statistics that we obtain from OpenFlow are also enriched with information from the domain or host extracted from the traffic inspection carried out by the framework, which provides a finer grain when it comes to dimensioning and analyzing the information.
During the framework development it could be distinguish two main blocks, first block is the part of capture the packets from the network. The network under study it is very simple, it consists of three hosts, one switch and one controller.  Second block is about processing the data gathered with the first part of the Thesis and obtain graphics to study the performance. The main data that we are going to study is number of packets per flow or number of Bytes per flow.
To deal with the task of this work, first, a brief review will be carried out of SDN networks and their applications, and then the monitoring framework will be implemented using the C and Python languages.
Once the framework is implemented, functional and performance tests will be accomplished in a controlled topology consisting of three hosts, a switch and an SDN controller to analyze the operating limits of the developed system. Validation tests will also be performed comparing the statistics and data extracted from the framework with data obtained with tshark that we would use as ground truth. Finally, the integration of the framework with a data representation system such as Grafana will be shown.


