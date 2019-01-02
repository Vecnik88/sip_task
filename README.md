Задание:

Нужно реализовать функцию parse_sip - разбор SIP пакета и вывод типа
сообщения: INVITE, ACK, BYE, CANCEL, REGISTER или OPTIONS.
(язык C, Linux)

Прототип функции:
	parse_sip(uint8_t *data);
uint8_t *data - указатель на начало данных пакета, который нужно разобрать.
Даны структуры eth_hdr, ip_hdr, udp_hdr, которыми можно пользоваться:

struct eth_hdr {
	uint8_t src[ETHER_ADDR_LEN];
	uint8_t dst[ETHER_ADDR_LEN];
	uint16_t ether_type;
}

struct ip_hdr {
	uint8_t version_ihl;
	uint8_t type_of_service;
	uint16_t total_length;
	uint16_t packet_id;
	uint16_t fragment_offset;
	uint8_t time_to_live;
	uint8_t next_proto_id;
	uint16_t header_checksum;
	uint32_t src;
	uint32_t dst;
}

struct udp_hdr {
	uint16_t src;
	uint16_t dst;
	uint16_t total_length;
	uint16_t checksum;
}

Все остальные структуры, если они понадобятся, необходимо определить
самостоятельно. Никакие вспомогательные функции вызывать не требуется.
Требуется определить, является ли пакет SIP пакетом (UDP src и dst порты - 5060).
Если является, то вывести сообщение «SIP packet type TYPE», где TYPE -
один из перечисленных выше типов (тип нужно определить, разобрав SIP
заголовок).

В приложении pcap.

Build and run(run only root):

	git clone https://github.com/Vecnik88/sip_task.git
	cd sip_task
	make
	sudo ./parse_sip -h
