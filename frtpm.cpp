#include <cstring>
#include <map>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <alsa/asoundlib.h>

typedef struct {
	uint16_t my_seq_nr;
	uint32_t peer_SSRC, my_SSRC;
	std::string peer_name;
} peer_t;

std::map<std::string, peer_t> peers;

constexpr char name[] = "frtpm";

snd_seq_t *open_client()
{
	snd_seq_t *handle = nullptr;
	int err = snd_seq_open(&handle, "default", SND_SEQ_OPEN_OUTPUT, 0);
	if (err < 0)
		return NULL;

	snd_seq_set_client_name(handle, name);

	return handle;
}

int my_new_port(snd_seq_t *const handle)
{
	return snd_seq_create_simple_port(handle, "out", SND_SEQ_PORT_CAP_READ | SND_SEQ_PORT_CAP_SUBS_READ, SND_SEQ_PORT_TYPE_MIDI_GENERIC);
}

void midisend(snd_seq_t *const seq, const int port, const uint8_t *data, const size_t n)
{
	snd_seq_event_t ev;
	snd_seq_ev_clear(&ev);
	snd_seq_ev_set_source(&ev, port);
	snd_seq_ev_set_subs(&ev);
	snd_seq_ev_set_direct(&ev);

	int cmd = data[0] & 0xf0;
	int ch = data[0] & 0x0f;

	if (cmd == 0x80 && n == 3)
		snd_seq_ev_set_noteoff(&ev, ch, data[1], data[2]);
	else if (cmd == 0x90 && n == 3)
		snd_seq_ev_set_noteon(&ev, ch, data[1], data[2]);
	else if (cmd == 0xc0 && n == 2)
		snd_seq_ev_set_pgmchange(&ev, ch, data[1]);
	else if (cmd == 0xf0)
		snd_seq_ev_set_sysex(&ev, n, (void *)data);
	else
		fprintf(stderr, "MIDI COMMAND %02x/%zu NOT EMULATED\n", data[0], n);

	snd_seq_event_output(seq, &ev);
	snd_seq_drain_output(seq);
}

uint64_t get_us()
{
	struct timespec tv;
	clock_gettime(CLOCK_REALTIME, &tv);

	return uint64_t(tv.tv_sec) * uint64_t(1000 * 1000) + uint64_t(tv.tv_nsec / 1000);
}

int create_udp_listen_socket(int port)
{
	struct sockaddr_in servaddr { 0 };
	int fd = -1;

	// Creating socket file descriptor
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	servaddr.sin_family = AF_INET; // IPv4
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(port);

	// Bind the socket with the server address
	if (bind(fd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	return fd; 
}

std::string get_endpoint_name(const struct sockaddr_in6 *addr, const socklen_t addr_len)
{
	char host[256] { "?" };
	char serv[256] { "?" };

	getnameinfo((struct sockaddr *)addr, addr_len, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV);

	return std::string(host) + "." + std::string(serv);
}

void process_command(const int work_fd, const int ctrl_fd, snd_seq_t *const seq, const int port, const uint8_t *const buffer, const int n, const sockaddr_in6 *const caddr, const socklen_t caddr_len)
{
	uint64_t now = get_us();

	std::string peer_addr = get_endpoint_name(caddr, caddr_len);

	printf("peer: %s\n", peer_addr.c_str());

	// HEADER
	uint8_t version = buffer[0] >> 6;

	if (buffer[0] == 0xff && buffer[1] == 0xff) {
		uint32_t peer_SSRC = ntohl(*(uint32_t *)&buffer[12]);

		if (buffer[2] == 'I' && buffer[3] == 'N') {
			uint32_t version = ntohl(*(uint32_t *)&buffer[4]);
			// Apple session setup
			if (version != 2)
				return;

			// uint32_t token = ntohl(*(uint32_t *)&buffer[8]);

			auto it = peers.find(peer_addr);
			if (it != peers.end()) {
				printf("Replacing session\n");
				peers.erase(it);
			}

			peer_t p;
			p.my_seq_nr = rand() & 0xffff;  // FIXME

			p.my_SSRC = rand() & 0xffffffff;  // FIXME
			p.peer_SSRC = peer_SSRC;

			p.peer_name = std::string((const char *)&buffer[16]);

			peers.insert(std::pair<std::string, peer_t>(peer_addr, p));

			printf("\tpeer name: %s\n", p.peer_name.c_str());

			// send reply
			uint8_t reply[1500];
			reply[0] = reply[1] = 0xff;
			reply[2] = 'O';
			reply[3] = 'K';
			reply[4] = reply[5] = reply[6] = 0x00;
			reply[7] = 0x02;
			memcpy(&reply[8], &buffer[8], 4);  // token
			*(uint32_t *)&reply[12] = htonl(p.my_SSRC);
			int name_len = strlen(name);
			memcpy(&reply[16], name, name_len + 1);

			if (sendto(work_fd, reply, 16 + name_len + 1, 0, (struct sockaddr *)caddr, caddr_len) == -1)
				perror("sendto");
		}
		else if (buffer[2] == 'B' && buffer[3] == 'Y') {
			printf("End of session\n");

			auto it = peers.find(peer_addr);
			if (it != peers.end())
				peers.erase(it);
			else
				printf("Peer already erased?\n");
		}
		else if (buffer[2] == 'C' && buffer[3] == 'K') {
			int count = buffer[8];

			auto it = peers.find(peer_addr);

			if (count == 0 && it != peers.end()) {
				uint8_t reply[1500];

				memcpy(reply, buffer, 36);

				*(uint32_t *)&reply[4] = htonl(it -> second.my_SSRC);
				reply[8] = 1;

				uint64_t work_now = now / 10;

				*(uint32_t *)&reply[20] = htonl(work_now >> 32);
				*(uint32_t *)&reply[24] = htonl(work_now & 0xffffffff);

				if (sendto(work_fd, reply, 36, 0, (struct sockaddr *)caddr, caddr_len) == -1)
					perror("sendto");
			}
		}
		else {
			printf("Unexpected Apple initiator command \"%c%c\"\n", buffer[2], buffer[3]);
		}

	}
	else if (version == 2) {  // RTP
		auto it = peers.find(peer_addr);

		if (it == peers.end()) {
			printf("Unknown session\n");
			return;
		}

		bool padding = buffer[0] & 32;
		if (padding) {
			printf("Has padding\n");
			return;
		}

		bool header_ext = buffer[0] & 16;
		if (header_ext) {
			printf("Has extended header\n");
			return;
		}

		uint8_t payload = buffer[1] & 127;
		if (payload != 0x61) {
			printf("Not MIDI: %02x\n", payload);
			return;
		}

		bool has_midi = buffer[1] & 1;
		if (!has_midi) {
			printf("Not MIDI\n");
			return;
		}

		uint16_t peer_seq_nr = (buffer[2] << 8) | buffer[3];

		uint32_t peer_SSRC = ntohl(*(uint32_t *)&buffer[8]);
		if (peer_SSRC != it->second.peer_SSRC) {
			printf("Unexpected peer %x (%x)\n", peer_SSRC, it->second.peer_SSRC);
			return;
		}

		// MIDI command
		const uint8_t *midi_command = &buffer[12];
	 	int data_left = n - 12;

		while(data_left > 0) {
			bool length_12b = midi_command[0] & 128;
			bool first_ts = midi_command[0] & 32;
			bool running_cmd = midi_command[0] & 16;

			const uint8_t *midi_data = &midi_command[1];

			uint16_t length = midi_command[0] & 15;
			if (length_12b) {
				length = (length << 8) | midi_command[1];
				midi_data = &midi_command[2];
				data_left -= 2;
			}
			else {
				data_left -= 1;
			}

			// FIXME process midi data
			printf("%02x %d [%d|%d|%d]\n\t", midi_command[0], length, length_12b, first_ts, running_cmd);
			for(int i=0; i<length; i++)
				printf("%02x ", midi_data[i]);
			printf("\n");
			midisend(seq, port, midi_data, length);

			data_left -= length;
		}

		// send reply (ack)
		uint8_t reply[1500];
		reply[0] = reply[1] = 0xff;
		reply[2] = 'R';
		reply[3] = 'S';
		*(uint32_t *)&reply[4] = htonl(peer_SSRC);
		*(uint16_t *)&reply[8] = htons(peer_seq_nr);
		reply[10] = reply[11] = 0x00;
		if (sendto(ctrl_fd, reply, 12, 0, (struct sockaddr *)caddr, caddr_len) == -1)
			perror("sendto");
	}
	else {
		printf("\tnot Apple (%02x %02x), not RTP header (%d)\n", buffer[0], buffer[1], version);
	}
}

int main(int argc, char *argv[])
{
  	snd_seq_t *seq = open_client();
  	int port = my_new_port(seq);

	int fd_ctrl = create_udp_listen_socket(5004);
	int fd_midi = create_udp_listen_socket(5005);

	struct pollfd fds[] = { { fd_ctrl, POLLIN | POLLERR, 0 }, { fd_midi, POLLIN, 0 } };

	for(;;) {
		uint8_t buffer[16384]; // that's bigger than jumbo frames

		struct sockaddr_in6 caddr { 0 };
		socklen_t caddr_len = sizeof caddr;

		poll(fds, 2, -1);

		if (fds[0].revents & POLLIN) {
			int n = recvfrom(fd_ctrl, (char *)buffer, sizeof buffer - 1, MSG_WAITALL, (struct sockaddr *)&caddr, &caddr_len);
			buffer[sizeof buffer - 1] = 0x00;

			process_command(fd_ctrl, fd_ctrl, seq, port, buffer, n, &caddr, caddr_len);
		}
		if (fds[0].revents & POLLERR) {
			printf("POLLERR\n");
		}

		if (fds[1].revents == POLLIN) {
			int n = recvfrom(fd_midi, (char *)buffer, sizeof buffer - 1, MSG_WAITALL, (struct sockaddr *)&caddr, &caddr_len);
			buffer[sizeof buffer - 1] = 0x00;

			process_command(fd_midi, fd_ctrl, seq, port, buffer, n, &caddr, caddr_len);
		}
	}

	snd_seq_close(seq);

	return 0;
}
