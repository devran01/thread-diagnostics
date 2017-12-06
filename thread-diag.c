/*
# Copyright (c) 2017 ARM Limited.
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
*/

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include <termios.h>
#include <sys/time.h>

#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

static int rtnl_sock = -1;
static int udp6_socket = -1;
static int rtnl_seq = 0;

static struct sockaddr_in6 thread_br_addr;
static char thread_br_addr_str[INET6_ADDRSTRLEN] = {0};
static uint16_t port_nr = 55000;
static int thread_diag_interval = 3600;

volatile sig_atomic_t thread_diag_forever = 0;

typedef struct thread_end_node_ip_addr
{
    //Assuming 255 end nodes
    char ip_addr[255][INET6_ADDRSTRLEN];
    uint8_t ip_addr_count;
}thread_end_node_ip_addr_t;

static thread_end_node_ip_addr_t thread_end_node_ip_addrs;

static void sighandler(int signal);
static int thread_diag_open_rtnl_socket();
static void thread_diag_setup_route(const struct in6_addr *addr,
                                const char * iface_name,
                                int metric, bool add
                            );

int get_ip_addr_thread_br(char * buf, int buf_len)
{
    int ret = -1;
    int serial_fd = open("/dev/ttyACM0", O_RDWR | O_NOCTTY);
    struct termios term;

    if (serial_fd < 0)  {
        syslog(LOG_ERR, "Unable open serial port /dev/ttyACM0, %s", strerror(errno));
        goto end;
    }

	if (tcflush(serial_fd, TCIOFLUSH) < 0) {
		syslog(LOG_ERR, "tcflush() %s\n", strerror(errno));
        goto end;
	}

	if (tcgetattr(serial_fd, &term) < 0) {
		syslog(LOG_ERR, "tcgetattr() %s\n", strerror(errno));
		goto end;
	}

    term.c_cflag |= (CREAD | CLOCAL);
    term.c_cflag &= ~CSIZE;
    term.c_cflag |= CS8;
    term.c_cflag &= ~CSTOPB;
    term.c_cflag &= ~PARENB;
    term.c_cflag &= ~CRTSCTS;

    term.c_iflag &= ~IGNPAR;
    term.c_iflag &= ~IGNBRK;
	term.c_iflag &= ~(IXON | IXOFF | IXANY);

	term.c_oflag = 0;
	term.c_lflag = 0;

	term.c_cc[VINTR]  = _POSIX_VDISABLE;
	term.c_cc[VQUIT]  = _POSIX_VDISABLE;
	term.c_cc[VSTART] = _POSIX_VDISABLE;
	term.c_cc[VSTOP]  = _POSIX_VDISABLE;
	term.c_cc[VSUSP]  = _POSIX_VDISABLE;
	term.c_cc[VEOF]   = _POSIX_VDISABLE;
	term.c_cc[VEOL]   = _POSIX_VDISABLE;
	term.c_cc[VERASE] = _POSIX_VDISABLE;
	term.c_cc[VKILL]  = _POSIX_VDISABLE;

    cfsetispeed(&term, B115200);
	cfsetospeed(&term, B115200);

	if (tcsetattr(serial_fd, TCSANOW, &term) < 0) {
        syslog(LOG_ERR, "tcsetattr() %s\n", strerror(errno));
		goto end;
	}

    int write_len = write(serial_fd, "echo off\n", strlen("echo off\n"));

    //TODO: Do not delete: We are writing "echo off\n" twice as for some reason
    //writing once isn't disabling the echo. Further investigation is required.
    write_len = write(serial_fd, "echo off\n", strlen("echo off\n"));

    sleep(1);

    if (tcflush(serial_fd, TCIOFLUSH) < 0) {
		syslog(LOG_ERR, "tcflush() %s\n", strerror(errno));
		goto end;
	}

    write_len = write(serial_fd, "radiogpaddr\n", strlen("radiogpaddr\n"));

    if (write_len < 0)  {
        syslog(LOG_ERR, "write() %s\n", strerror(errno));
		goto end;
	}

    sleep(2);

    fd_set set;
    struct timeval tv;
    FD_ZERO(&set);
	FD_SET(serial_fd, &set);
	tv.tv_sec = 1;
	tv.tv_usec = 0;

    int ret_sel = select(serial_fd+1, &set, NULL, NULL, &tv);

    if (ret_sel == 1)   {
        int read_len = read(serial_fd, buf, buf_len);
        if (read_len < 0)  {
            syslog(LOG_ERR, "read() %s\n", strerror(errno));
		    goto end;
	    }

        ret = 0;
    } else    {
        //TODO: Handle timeout error
        syslog(LOG_DEBUG, "error: %s\n", strerror(errno));
    }

end:
    write_len = write(serial_fd, "echo on\n", strlen("echo on\n"));
    close(serial_fd);
    if(!ret)
        return 0;
    else
        return -1;

}

static void sighandler(int signal)
{
	syslog(LOG_ERR, "singal handler called with %d signal", signal);
    thread_diag_forever = 1;
}

int main(int argc, char * argv[])
{

    struct ifreq ifr;

    const char command[] = "thread diag ";
    const char params[]  =  " --req 00:01:02:04:05:06:07:08:09";

    openlog("thread-diag", LOG_PERROR | LOG_PID, LOG_DAEMON);
	//TODO: setlogmask(LOG_UPTO(LOG_WARNING));
    setlogmask(LOG_UPTO(LOG_DEBUG));

    if (argc < 2)   {
        syslog(LOG_ERR, "The interval is required");
        syslog(LOG_ERR, "Usage:");
        syslog(LOG_ERR, "thread-diag <interval>");
        closelog ();
        return 2;
    }

    FILE *fp = fopen("/var/run/thread_diag.pid", "r+");
    char thread_diag_pid_str[10];

    if (!fp) {
        fp = fopen("/var/run/thread_diag.pid", "w");

        sprintf(thread_diag_pid_str, "%d\n",getpid());
        if(strlen(thread_diag_pid_str) != fwrite(thread_diag_pid_str, 1, strlen(thread_diag_pid_str), fp))
            syslog(LOG_ERR, "Unable to write the PID into file /var/run/thread_diag.pid");
    }   else   {
        sprintf(thread_diag_pid_str, "%d\n",getpid());
        if(strlen(thread_diag_pid_str) != fwrite(thread_diag_pid_str, 1, strlen(thread_diag_pid_str), fp))
            syslog(LOG_ERR, "Unable to write the PID into file /var/run/thread_diag.pid");
    }

    fclose(fp);


    char buf[4096];
    while(1)    {
        if (get_ip_addr_thread_br(buf, sizeof(buf)) < 0)    {
            syslog(LOG_ERR, "Unable to get thread border router ip address from serial port");
            sleep(5);
        } else  {
            break;
        }
    }

    strcpy(thread_br_addr_str, strtok (buf,"\r\n"));

    if ((rtnl_sock = thread_diag_open_rtnl_socket()) < 0)
        return 2;

    udp6_socket = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (udp6_socket < 0 )   {
        syslog(LOG_ERR, "Unable to open a UDP socket: %s", strerror(errno));
        return 2;
    }

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "eth1");
    if (setsockopt(udp6_socket, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        syslog(LOG_ERR, "Unable to bind the socket to LAN interface: %s", strerror(errno));
        return 2;
    }

    struct timeval udp6_socket_timeout={20,0};
    if(setsockopt(udp6_socket,SOL_SOCKET,SO_RCVTIMEO,(void *)&udp6_socket_timeout,sizeof(udp6_socket_timeout)) < 0)    {
        syslog(LOG_ERR, "Unable to set timeout on socket: %s", strerror(errno));
        return 2;
    }

    thread_diag_interval = atoi(argv[1]);

    syslog(LOG_DEBUG, "The thread border router IPv6 address : %s, port number: %d and interval: %d", thread_br_addr_str, port_nr, thread_diag_interval);

    memset(&thread_br_addr, 0, sizeof(thread_br_addr));
    thread_br_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, thread_br_addr_str, &thread_br_addr.sin6_addr);
    thread_br_addr.sin6_port = htons(port_nr);

    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = sighandler;
    sigaction(SIGTERM, &action, NULL);

    while(!thread_diag_forever)    {

        uint16_t payload_len = strlen("thread route") + 1;
        char * payload = malloc(payload_len);
        if(!payload)    {
            syslog(LOG_ERR, "malloc failed %s\n", strerror(errno));
            thread_diag_forever = 1;
            continue;
        }
        strcpy(payload, "thread route");

        if (sendto(udp6_socket, payload, payload_len, 0,
                (struct sockaddr *)&thread_br_addr,
                sizeof(thread_br_addr)) < 0) {

            thread_diag_setup_route(&thread_br_addr.sin6_addr, "eth1", 128, true);

            if (sendto(udp6_socket, payload, payload_len, 0,
                (struct sockaddr *)&thread_br_addr,
                sizeof(thread_br_addr)) < 0)    {
                    syslog(LOG_ERR, "Unable to send thread route command to border router: %s", strerror(errno));
                    thread_diag_setup_route(&thread_br_addr.sin6_addr, "eth1", 128, false);
                    free(payload);
                    sleep(thread_diag_interval);
                    continue;
                }
            thread_diag_setup_route(&thread_br_addr.sin6_addr, "eth1", 128, false);
        }

        free(payload);

        char buffer[1480];
        if (recvfrom(udp6_socket, buffer, 1480, 0,
                0, 0) <= 0) {
            syslog(LOG_ERR, "Unable to get thread route command output from the border router: %s", strerror(errno));
            sleep(thread_diag_interval);
            continue;
        }

        thread_end_node_ip_addrs.ip_addr_count = 0;
        char * token = strtok (buffer,"\n");
        while(token)   {
            char * p_val = strchr(token, '/');
            if(p_val)   {
                token[p_val-token] = 0;
                strcpy(thread_end_node_ip_addrs.ip_addr[thread_end_node_ip_addrs.ip_addr_count],++token);
                thread_end_node_ip_addrs.ip_addr_count++;
            }
            token = strtok (NULL,"\n");
        }

        sleep(1);

        while(thread_end_node_ip_addrs.ip_addr_count > 0)    {
            thread_end_node_ip_addrs.ip_addr_count--;

            //payload = command + address + params
            payload_len = strlen(command) + strlen(thread_end_node_ip_addrs.ip_addr[thread_end_node_ip_addrs.ip_addr_count]) + strlen(params) + 1;
            payload = malloc(payload_len);
            if(!payload)    {
                syslog(LOG_ERR, "malloc failed %s\n", strerror(errno));
                thread_diag_forever = 1;
                break;
            }
            strcpy(payload, command);
            strcat(payload, thread_end_node_ip_addrs.ip_addr[thread_end_node_ip_addrs.ip_addr_count]);
            strcat(payload, params);

            if (sendto(udp6_socket, payload, payload_len, 0,
                    (struct sockaddr *)&thread_br_addr,
                    sizeof(thread_br_addr)) < 0) {

                thread_diag_setup_route(&thread_br_addr.sin6_addr, "eth1", 128, true);

                if (sendto(udp6_socket, payload, payload_len, 0,
                    (struct sockaddr *)&thread_br_addr,
                    sizeof(thread_br_addr)) < 0)    {
                        syslog(LOG_ERR, "Unable to send thread diag commands to border router: %s\n", strerror(errno));
                        thread_diag_setup_route(&thread_br_addr.sin6_addr, "eth1", 128, false);
                        free(payload);
                        continue;
                    }
                thread_diag_setup_route(&thread_br_addr.sin6_addr, "eth1", 128, false);
            }

            free(payload);

            if (recvfrom(udp6_socket, buffer, 1480, 0,
                    0, 0) <= 0) {
                syslog(LOG_ERR, "Unable to receive thread diag output from %s, %s\n", thread_end_node_ip_addrs.ip_addr[thread_end_node_ip_addrs.ip_addr_count], strerror(errno));
                continue;
            }

            uint8_t index = 0;
            char * thread_diag_data[9];
            token = strtok (buffer,"\n");
            while(token)   {
                char * p_val = strchr(token, '=');
                if(p_val)   {
                    thread_diag_data[index] = ++p_val;
                    index++;
                }
                token = strtok (NULL,"\n");
            }

            if(!strcmp(thread_br_addr_str, thread_end_node_ip_addrs.ip_addr[thread_end_node_ip_addrs.ip_addr_count]))   {
                char diag_tmpl[] = "Hostname | IPv6 Address | Short Address | Mode | Connectivity | Route Information | Leader Data | Network Data";
                syslog(LOG_INFO, "%s", diag_tmpl);

                char diag_data[1480];
                strcpy(diag_data, "mbedAP");
                strcat(diag_data, " | ");
                strcat(diag_data, thread_br_addr_str);
                strcat(diag_data, " | ");
                strcat(diag_data, thread_diag_data[1]);
                strcat(diag_data, " | ");
                strcat(diag_data, thread_diag_data[2]);
                strcat(diag_data, " | ");
                strcat(diag_data, thread_diag_data[3]);
                strcat(diag_data, " | ");
                strcat(diag_data, thread_diag_data[4]);
                strcat(diag_data, " | ");
                strcat(diag_data, thread_diag_data[5]);
                strcat(diag_data, " | ");
                strcat(diag_data, thread_diag_data[6]);
                syslog(LOG_INFO, "%s", diag_data);

                char diag_tmpl1[] = "Address List | MAC Counters";
                syslog(LOG_INFO, "%s", diag_tmpl1);
                strcpy(diag_data, thread_diag_data[7]);
                strcat(diag_data, " | ");
                strcat(diag_data, thread_diag_data[8]);
                syslog(LOG_INFO, "%s", diag_data);
            }
            else    {
                char diag_tmpl[] = "Hostname | IPv6 Address | Short Address | Mode | Connectivity | Leader Data | Network Data";
                syslog(LOG_INFO, "%s", diag_tmpl);

                char diag_data[1480];
                strcpy(diag_data, "Thread End Node");
                strcat(diag_data, " | ");
                strcat(diag_data, thread_end_node_ip_addrs.ip_addr[thread_end_node_ip_addrs.ip_addr_count]);
                strcat(diag_data, " | ");
                strcat(diag_data, thread_diag_data[1]);
                strcat(diag_data, " | ");
                strcat(diag_data, thread_diag_data[2]);
                strcat(diag_data, " | ");
                strcat(diag_data, thread_diag_data[3]);
                strcat(diag_data, " | ");
                strcat(diag_data, thread_diag_data[4]);
                strcat(diag_data, " | ");
                strcat(diag_data, thread_diag_data[5]);
                syslog(LOG_INFO, "%s", diag_data);

                char diag_tmpl1[] = "Address List | MAC Counters";
                syslog(LOG_INFO, "%s", diag_tmpl1);
                strcpy(diag_data, thread_diag_data[6]);
                strcat(diag_data, " | ");
                strcat(diag_data, thread_diag_data[7]);
                syslog(LOG_INFO, "%s", diag_data);
            }

            sleep(1);
        }

        sleep(thread_diag_interval);
    }

    close(udp6_socket);
    //close the system log
    closelog ();
}

static int thread_diag_open_rtnl_socket()
{
    int sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);

	// Connect to the kernel netlink interface
	struct sockaddr_nl nl = {.nl_family = AF_NETLINK};
	if (connect(sock, (struct sockaddr*)&nl, sizeof(nl))) {
		syslog(LOG_ERR, "Failed to connect to kernel rtnetlink: %s",
				strerror(errno));
		return -1;
	}

	return sock;
}

static void thread_diag_setup_route(const struct in6_addr *addr,
                                const char * iface_name,
                                int metric, bool add
                            )
{
	struct req {
		struct nlmsghdr nh;
		struct rtmsg rtm;
		struct rtattr rta_dst;
		struct in6_addr dst_addr;
		struct rtattr rta_oif;
		uint32_t ifindex;
		struct rtattr rta_table;
		uint32_t table;
		struct rtattr rta_prio;
		uint32_t prio;
	} req = {
		{sizeof(req), 0, NLM_F_REQUEST, ++rtnl_seq, 0},
		{AF_INET6, 128, 0, 0, 0, 0, 0, 0, 0},
		{sizeof(struct rtattr) + sizeof(struct in6_addr), RTA_DST},
		*addr,
		{sizeof(struct rtattr) + sizeof(uint32_t), RTA_OIF},
        if_nametoindex(iface_name),
		{sizeof(struct rtattr) + sizeof(uint32_t), RTA_TABLE},
		RT_TABLE_MAIN,
		{sizeof(struct rtattr) + sizeof(uint32_t), RTA_PRIORITY},
		metric
	};

	if (add) {
		req.nh.nlmsg_type = RTM_NEWROUTE;
		req.nh.nlmsg_flags |= NLM_F_CREATE;
		req.rtm.rtm_protocol = RTPROT_STATIC;
		req.rtm.rtm_scope = RT_SCOPE_LINK;
		req.rtm.rtm_type = RTN_UNICAST;
	} else {
		req.nh.nlmsg_type = RTM_DELROUTE;
		req.rtm.rtm_scope = RT_SCOPE_NOWHERE;
	}

	req.nh.nlmsg_len = sizeof(req);
	send(rtnl_sock, &req, req.nh.nlmsg_len, MSG_DONTWAIT);
}
