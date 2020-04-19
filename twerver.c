#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include "socket.h"

#ifndef PORT
    #define PORT 59837
#endif

#define LISTEN_SIZE 5
#define WELCOME_MSG "Welcome to My Twitter! Enter your username: "
#define SEND_MSG "send"
#define SHOW_MSG "show"
#define FOLLOW_MSG "follow"
#define UNFOLLOW_MSG "unfollow"
#define BUF_SIZE 256
#define MSG_LIMIT 8
#define FOLLOW_LIMIT 5

struct client {
    int fd;
    struct in_addr ipaddr;
    char username[BUF_SIZE];
    char message[MSG_LIMIT][BUF_SIZE];
    struct client *following[FOLLOW_LIMIT]; // Clients this user is following
    struct client *followers[FOLLOW_LIMIT]; // Clients who follow this user
    char inbuf[BUF_SIZE]; // Used to hold input from the client
    char *in_ptr; // A pointer into inbuf to help with partial reads
    struct client *next;
};


// Provided functions. 
void add_client(struct client **clients, int fd, struct in_addr addr);
void remove_client(struct client **clients, int fd);

// These are some of the function prototypes that we used in our solution 
// You are not required to write functions that match these prototypes, but
// you may find them helpful when thinking about operations in your program.

// Send the message in s to all clients in active_clients. 
void announce(struct client **active_clients, char *s);

// Move client c from new_clients list to active_clients list. 
void activate_client(struct client *c, 
    struct client **active_clients_ptr, struct client **new_clients_ptr);

// unfollow all the clients from p's following list and make p's follower
// unfollow p from their following list
void unfollow_all(struct client *p, struct client **active_clients);

// announce disconnection tof the client to all the other active clients
void announce_goodbye(struct client **active_clients, char *username);

// The set of socket descriptors for select to monitor.
// This is a global variable because we need to remove socket descriptors
// from allset when a write to a socket fails. 
fd_set allset;

/*
 * Create a new client, initialize it, and add it to the head of the linked
 * list.
 */
void add_client(struct client **clients, int fd, struct in_addr addr) {
    struct client *p = malloc(sizeof(struct client));
    if (!p) {
        perror("malloc");
        exit(1);
    }
    printf("Adding client %d %s\n", fd, inet_ntoa(addr));
    p->fd = fd;
    p->ipaddr = addr;
    p->username[0] = '\0';
    p->in_ptr = p->inbuf;
    p->inbuf[0] = '\0';
    p->next = *clients;
    for (int i = 0; i < FOLLOW_LIMIT; i++) {
    	p->following[i] = NULL;
    	p->followers[i] = NULL;
    }
    // initialize messages to empty strings
    for (int i = 0; i < MSG_LIMIT; i++) {
        p->message[i][0] = '\0';
    }

    *clients = p;
}

/*
 * Remove client from the linked list and close its socket.
 * Also, remove socket descriptor from allset.
 */
void remove_client(struct client **clients, int fd) {
    struct client **p;

    for (p = clients; *p && (*p)->fd != fd; p = &(*p)->next);

    // Now, p points to (1) top, or (2) a pointer to another client
    // This avoids a special case for removing the head of the list
    if (*p) {
        // Remove the client from other clients' following/followers
        // lists
        unfollow_all(*p, clients);
        // Remove the client
        struct client *t = (*p)->next;
        printf("Disconnect from %s\n", inet_ntoa((*p)->ipaddr));
        printf("Removing client %d %s\n", fd, inet_ntoa((*p)->ipaddr));
        FD_CLR((*p)->fd, &allset);
        if (close((*p)->fd) == -1) {
        	perror("closing client fd\n");
        	exit(1);
        }
        free(*p);
        *p = t;
    } else {
        fprintf(stderr, 
            "Trying to remove fd %d, but I don't know about it\n", fd);
    }
}

/* Move client c from new_clients list to active_clients list. 
*/
void activate_client(struct client *c, 
					 struct client **active_clients_ptr, struct client **new_clients_ptr) {
	// add client c to active_clients list and set its username.
	add_client(active_clients_ptr, c->fd, c->ipaddr);
	strncat((*active_clients_ptr)->username, c->inbuf, strlen(c->inbuf));

	// remove the client from new_clients list.
	struct client **p;
    for (p = new_clients_ptr; *p && (*p)->fd != c->fd; p = &(*p)->next);

    // Now, p points to (1) top, or (2) a pointer to another client
    // This avoids a special case for removing the head of the list
    if (*p) {
        // Remove the client from new_clients list and free its memory allocation
        struct client *t = (*p)->next;
        printf("Removing client %d %s from new_clients\n", c->fd, inet_ntoa((*p)->ipaddr));
		free(*p);
        *p = t;
    } else {
    // if the program reaches, here something is wrong
        fprintf(stderr, 
            "Trying to remove fd %d, but I don't know about it\n", c->fd);
    }
    
	// create a message that will inform all active clients that c has joined the server
	int num = strlen((*active_clients_ptr)->username) + strlen(" has just joined.\n") + 1;
	char msg[num];
	msg[0] = '\0';
	strncat(msg, (*active_clients_ptr)->username, strlen((*active_clients_ptr)->username));
	strncat(msg, " has just joined.\n", strlen(" has just joined.\n"));
	// announce the message to all the active clients
	announce(active_clients_ptr, msg);
}

/* write the msg to client_fd socket and remove the client from clients list if an error occurs 
* while writing to the socket.
*/
void write_to_client(int client_fd, char *msg, struct client **clients) {
	if ((write(client_fd, msg, strlen(msg))) != strlen(msg)) {
			fprintf(stderr, "Write to client socket failed\n");
			struct client **p;
    		for (p = clients; *p && (*p)->fd != client_fd; p = &(*p)->next);
    		char *username = (*p)->username;
    		// notify other active clients that p has disconnected
			announce_goodbye(clients, username);
			// remove client from the client list
			remove_client(clients, client_fd);
	}
}

/* Send a message that is up to 140 characters long to all the client p's follower.
* If p has already sent MSG_LIMIT messages, notfiy p ans dont send the message.
*/
void send_messages(struct client *p, char *message, struct client **active_clients) {
	// copy the message to message array of client p and check if p has sent maximum no. 
	// messages
	int msg_flag = 1;
	for (int i = 0; i < MSG_LIMIT; i++) {
        if (p->message[i][0] == '\0') {
        	msg_flag = 0;
        	strcpy(p->message[i], message);
        	break;
        }
    }
    // Notfiy the client that they have sent maximum no. of messages
    if (msg_flag == 1) {
    	char *msg = "Maximum number of messages sent reached. Cannot send more!\n";
		write_to_client(p->fd, msg, active_clients);
    }
    // Display the message to all followers of client p
    else {
    	// Create the customized message that will have client's username
    	int msg_len = strlen(p->username) + strlen(": ") + strlen(message) + 2;
		char msg[msg_len];
		msg[0] = '\0';
		strncat(msg, p->username, strlen(p->username));
		strncat(msg, ": ", 2);
		strncat(msg, message, strlen(message));
		strncat(msg, "\n", 1);
		// Write the message to the client socket of all the followers
    	for (int i = 0; i < FOLLOW_LIMIT; i++) {
    		if (p->followers[i] != NULL) {
    			int follower_fd = ((p->followers)[i])->fd;
    			write_to_client(follower_fd, msg, active_clients);
			}
		}
	}
}

/* Check whether client p already follows the other client or not. If they do return 1
* else return 0
*/
int check_follow_status(struct client *p, struct client *client_following) {
	for (int i = 0; i < FOLLOW_LIMIT; i++) {
		// check of client is in p's following list
		if ((p->following)[i] != NULL) {
			if (strcmp(((p->following)[i])->username, client_following->username) == 0) {
				return 1;
			}
		}
		// check if p is in client's list of followers
		if ((client_following->followers)[i] != NULL)  {
			if (strcmp(((client_following->followers)[i])->username, p->username) == 0) {
				return 1;
			}
		}
	}
	return 0;
}

/* make client p follow the username by adding the client to p's following list and adding p
* to client's list of followers. If p already has followed FOLLOW_LIMIT users reject the follow
* request and inform the client.
*/
void follow(struct client *p, struct client *client_following, struct client **active_clients) {
	if (p != NULL && client_following != NULL) {
		for (int i = 0; i < FOLLOW_LIMIT; i++) {
			//  check whether client p already follows the other client
			if (check_follow_status(p, client_following) == 1) {
				char *message = "User is already followed!\n";
				write_to_client(p->fd, message, active_clients);
			}
		}
		int null_index1 = -1;
		int null_index2 = -1;
		// check if p has reached its maximum following capacity
		for (int i = 0; i < FOLLOW_LIMIT; i++) {
			if ((p->following)[i] == NULL) {
				null_index1 = i;
				break;
			}
		}
		// check if the client has reached the maximum followers capacity
		for (int i = 0; i < FOLLOW_LIMIT; i++) {
			if ((client_following->followers)[i] == NULL) {
				null_index2 = i;
				break;
			}
		};
		// inform p about client reaching the follower capacity
		if (null_index1 == -1) {
			char *message = "Maximum follower capacity of user reached. Cannot follow this user.!\n";
			write_to_client(p->fd, message, active_clients);
		}
		// inform p about reacing its following capacity
		else if (null_index2 == -1) {
			char *message = "Maximum following capacity reached. Couldnt follow more!\n";
			write_to_client(p->fd, message, active_clients);
		}
		else {
			// add the client to p's following list and add p to client's list of followers
			// and inform the client that p follows them
			p->following[null_index1] = client_following;
			printf("%s is following %s\n", p->username, client_following->username);
			(client_following->followers)[null_index2] = p;
			printf("%s has %s as a follower\n", client_following->username, p->username);
			// create the message to inform the client that p follows them
			char msg[strlen(p->username) + strlen(" follows you\n")];
			msg[0] = '\0';
			strncat(msg, p->username, strlen(p->username));
			strncat(msg, " follows you\n", strlen(" follows you\n"));
			write_to_client(client_following->fd, msg, active_clients);
		}
	}
}

/* make p unfollow the other client by removing them from p's following list and remove p 
* from client's list of followers. If unsuccessful, notify p
*/
void unfollow(struct client *p, struct client *client_following, struct client **active_clients) {
	if (p != NULL && client_following != NULL) {
		int unfollow_flag = 1;
		for (int i = 0; i < FOLLOW_LIMIT; i++) {
			if ((client_following->followers)[i] != NULL) {
				// remove p from client's list of followers if p is found
				if (strcmp(((client_following->followers)[i])->username, p->username) == 0) {
					client_following->followers[i] = NULL;
					unfollow_flag = 0;
					printf("%s no longer has %s as a follower\n", client_following->username
															, p->username);
					char msg[strlen(p->username) + strlen(" no longer follows you\n")];
					msg[0] = '\0';
					strncat(msg, p->username, strlen(p->username));
					strncat(msg, " no longer follows you\n", strlen(" no longer follows you\n"));
					write_to_client(client_following->fd, msg, active_clients);
				}
			}
			if ((p->following)[i] != NULL) {
				// remove the client from p's following list if the other client is found
				if (strcmp(((p->following)[i])->username, client_following->username) == 0) {
					p->following[i] = NULL;
					unfollow_flag = 0;
					printf("%s unfollows %s\n", p->username, client_following->username);
				}
			}
		}
		// if the client is not in p's following list, inform p that it does not follow the user
		if (unfollow_flag == 1) {
			char *msg = "You dont follow this user\n";
			write_to_client(p->fd, msg, active_clients);
		}
	}
}

/* remove p from all the clients's following list if these clients lie in p's list of followers
* make p unfollow all the clients that lie in its followins list
*/
void unfollow_all(struct client *p, struct client **active_clients) {
	for (int i = 0; i < FOLLOW_LIMIT; i++) {
		// make p's followers unfollow p
		struct client *client_follower = p->followers[i];
		if (client_follower != NULL) {
			int j = 0;
			while (((client_follower->following)[j])->fd != p->fd) {
				j++;
			}
			client_follower->following[j] = NULL;
			printf("%s no longer follows %s as they have disconnected\n", 
					client_follower->username, p->username);
		}
		// remove p from client's list of followers
		struct client *client_following = p->following[i];
		unfollow(p, client_following, active_clients);
	}
}

/* Send the message in s to all clients in active_clients.
*/
void announce(struct client **active_clients, char *s) {
	struct client *active_c = *active_clients;
	while (active_c != NULL) {
		write_to_client(active_c->fd, s, active_clients);
		active_c = active_c->next;
	}
}

/* announce the disconnection of client from server to all the other active clients
*/
void announce_goodbye(struct client **active_clients, char *username) {
    int msg_len = strlen(username) + strlen("Goodbye ") + 2;
    char msg[msg_len];
    msg[0] = '\0';
    strncat(msg, "Goodbye ", strlen("Goodbye "));
    strncat(msg, username, strlen(username));
    strcat(msg, "\n");
    struct client *active_c = *active_clients;
	while (active_c != NULL) {
		if (strcmp(active_c->username, username) != 0) {
			write_to_client(active_c->fd, msg, active_clients);
		}
		active_c = active_c->next;
	}
}

/* Display the previously sent messages of clients that p is following.
*/
void show(struct client *p, struct client **active_clients) {
	for (int i = 0; i < FOLLOW_LIMIT; i++) {
		// iterate through p's following list
		struct client *client_following = p->following[i];
		if (client_following != NULL) {
			printf("Displaying %s's messages to %s\n", client_following->username, p->username);
			// iterate through the client p follows message list
			for (int i = 0; i < MSG_LIMIT && client_following->message[i][0] != '\0'; i++) {
				// create the customised message that will be displayed to p
				int msg_len = strlen(client_following->username) + strlen(" wrote: ") 
								+ strlen((client_following->message)[i]) + 2;
				char msg[msg_len];
				msg[0] = '\0';
				strncat(msg, client_following->username, strlen(client_following->username));
				strncat(msg, " wrote: ", strlen(" wrote: "));
				strncat(msg, client_following->message[i], strlen((client_following->message)[i]));
				strncat(msg, "\n", 1);
				// write message to p's socket
				write_to_client(p->fd, msg, active_clients);
			}
		}
	}
}

/* Handle the input that the new client enters as it's username in p->inbuf and return 0 if successful,
* else return 1
*/
int handle_new_client(struct client *p, struct client **new_clients, struct client **active_clients) {
	struct client *temp_client = *active_clients;
	int username_flag = 1;
	// check whether the username entered is in use by other active clients
	while (temp_client != NULL) {
		if (strcmp(temp_client->username, p->inbuf) != 0) {
			temp_client = temp_client->next;
		}
		else {
			username_flag = 0;
			break;
		}
	}
	// Notify the client that the username is in use
	if (username_flag == 0) {
		char *message = "Username is already in use. Please enter again!\n";
		write_to_client(p->fd, message, new_clients);
		strcpy(p->inbuf, "\0");
		return 1;
	}
	// if the username entered is empty, notify the user that the command is Invalid
	if (strlen(p->inbuf) == 0) {
		char *message = "Invalid command. Please enter username again!\n";
		write_to_client(p->fd, message, new_clients);
		return 1;
	}
	// Since no flags were raised return 0 indicating that the entered username is valid
	else {
		return 0;
	}
}

/* handle the follow command the active client p has entered. If successful pass the follow
* request otherwise notify p
*/
void handle_follow(char *parameter, struct client **active_clients, struct client *p) {
	// check if the parameter entered is same as p's username
	if (strcmp(parameter, p->username) == 0) {
		char *message = "You cannot follow yourself\n";
		write_to_client(p->fd, message, active_clients);
	}
	else {
		// check if the parameter entered matches the username of any active client
		int follow_flag = 1;
		struct client *temp_client = *active_clients;
		while (temp_client != NULL) {
			// if match found, send the follow request to follow function
			if (strcmp(temp_client->username, parameter) == 0) {
				follow_flag = 0;
				follow(p, temp_client, active_clients);
				break;
			}
			temp_client = temp_client->next;
		}
		// if no match found, notify p that entered username does not exist
		if (follow_flag == 1) {
			char *message = "Invalid command. Username does not exists\n";
			write_to_client(p->fd, message, active_clients);
		}
	}
}

/* handle the follow command the active client p has entered. If successful pass the follow
* request otherwise notify p
*/
void handle_unfollow(char *parameter, struct client **active_clients, struct client *p) {
	// check if the parameter entered is same as p's username
	if (strcmp(parameter, p->username) == 0) {
		char *message = "You cannot unfollow yourself\n";
		write_to_client(p->fd, message, active_clients);
	}
	else {
		// check if the parameter entered matches the username of any active client
		int unfollow_flag = 1;
		struct client *temp_client = *active_clients;
		while (temp_client != NULL) {
			// if match found send the unfollow request to unfolloe function
			if (strcmp(temp_client->username, parameter) == 0) {
				unfollow_flag = 0;
				unfollow(p, temp_client, active_clients);
				break;
			}
			temp_client = temp_client->next;
		}
		// if no match is found, notify p that the entered username does not exist
		if (unfollow_flag == 1) {
			char *msg = "Invalid command. Username does not exists\n";
			write_to_client(p->fd, msg, active_clients);
		}
	}
}

/* handle the send command the active client p has requested. if successful, pass the send command
* send_messages method otherwise notfiy the user
*/
void handle_send(char *parameter, struct client **active_clients, struct client *p) {
	// check whether the entered message exceeds 140 character or not
	if (strlen(parameter) > 140) {
		char *msg = "Message exceeds 140 character. Please enter a message <= 140 characters\n";
		write_to_client(p->fd, msg, active_clients);
	}
	// if no flag were raised. send the parameter to send_messages function
	else {
		send_messages(p, parameter, active_clients);
	}
}
/*
* handle the active client p's input in p->inbuf and call the correct function if the command
* and paramter passed are valid; otherwise inform p
*/
void handle_active_client(struct client *p, struct client **active_clients) {
	printf("%s: %s\n", p->username, p->inbuf);
	// find the first occurence of ' ' in p->inbuf
	char *user_input = strchr(p->inbuf, ' ');
	// if no occurence of ' ' is found
	if (user_input == NULL) {
		// check is input matches "quit" or "show"
		if (strcmp(p->inbuf, "quit") == 0) {
			char *username = p->username;
			announce_goodbye(active_clients, username);
			remove_client(active_clients, p->fd);
		}
		else if (strcmp(p->inbuf, "show") == 0) {
			show(p, active_clients);
		}
		// notify p that the entered input is not valid command
		else {
			char *message = "Invalid command. Please enter a valid command\n";
			write_to_client(p->fd, message, active_clients);
		}
	}
	else {
		// extract the command and parameter into two seperate char array
		int size_c = strlen(p->inbuf) - strlen(user_input) + 1;
		char command[size_c];
		int size_p = strlen(user_input);
		char parameter[size_p];
		strncpy(command, p->inbuf, size_c - 1);
		strncpy(parameter, user_input + 1, size_p - 1);
		command[size_c - 1] = '\0';
		parameter[size_p - 1] = '\0';
		// check whether command or parameter points to empty strings
		if (strlen(parameter) == 0 || strlen(command) == 0) {
			char *message = "You cannot enter empty command\n";
			write_to_client(p->fd, message, active_clients);
		}
		// call the appropiate handle function based on which command function
		// the entered command matches otherwise notify the user
		else {
			if (strcmp(command, "follow") == 0) {
				handle_follow(parameter, active_clients, p);
			}
			else if (strcmp(command, "unfollow") == 0) {
				handle_unfollow(parameter, active_clients, p);
			}
			else if (strcmp(command, "send") == 0) {
				handle_send(parameter, active_clients, p);
			}
			// notify p that thhe entered command is invalid
			else {
				char *msg = "Invalid command. Please enter a valid command\n";
				write_to_client(p->fd, msg, active_clients);
			}
		}
	}
}

/*
 * Search the first n character of buf for (\r\n).
 * Return one plus the index of '\n' of the first network newline,
 * or -1 if no network newline is found.
*/
int find_network_newline(const char *buf, int n) {
	for (int i = 0; i < n; i++) {
		if (buf[i] == '\r' && buf[i+1] == '\n') {
			return i+2;
		}
	}
	return -1;
}

/* Partial read the client buffer to find the entered input by the client
* Fill p->inbuf with the entered input and return 0 if successful. If read
* call is unsuccessful, reutrn -1
*/
int read_client_buffer(struct client *p) {
    int inbuf = 0;
    int room = sizeof(p->inbuf);
    p->in_ptr = p->inbuf;
    // set after to p->in_ptr so that after always point to start of p->inbuf
    // and we dont change p->in_ptr
    char *after = p->in_ptr;
    int nbytes;
    while ((nbytes = read(p->fd, after, room)) > 0) {
     	// update inbuf
    	inbuf += nbytes;
       	int where;
       	//Keep on filling to p->inbuf untill find the network newline character
       	printf("[%d] Read %d bytes\n", p->fd, nbytes);
       	while ((where = find_network_newline(p->inbuf, inbuf)) > 0) {
       		// add the null point character to p->inbuf
        	p->inbuf[where - 2] = '\0';
        	printf("[%d] Found newline: %s\n", p->fd, p->inbuf);
        	// update inbuf again and return 0
        	inbuf -= where;
        	return 0;
        }
        // update after and room for the next read.
        after = p->inbuf + inbuf;
        room = sizeof(p->inbuf) - inbuf;
    }
    // if read call fails return -1
    return -1;
}

int main (int argc, char **argv) {
    int clientfd, maxfd, nready;
    struct client *p;
    struct sockaddr_in q;
    fd_set rset;
    // If the server writes to a socket that has been closed, the SIGPIPE
    // signal is sent and the process is terminated. To prevent the server
    // from terminating, ignore the SIGPIPE signal. 
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    // A list of active clients (who have already entered their names). 
    struct client *active_clients = NULL;

    // A list of clients who have not yet entered their names. This list is
    // kept separate from the list of active clients, because until a client
    // has entered their name, they should not issue commands or 
    // or receive announcements. 
    struct client *new_clients = NULL;

    struct sockaddr_in *server = init_server_addr(PORT);
    int listenfd = set_up_server_socket(server, LISTEN_SIZE);
	free(server);
    // Initialize allset and add listenfd to the set of file descriptors
    // passed into select 
    FD_ZERO(&allset);
    FD_SET(listenfd, &allset);

    // maxfd identifies how far into the set to search
    maxfd = listenfd;

    while (1) {
        // make a copy of the set before we pass it into select
        rset = allset;

        nready = select(maxfd + 1, &rset, NULL, NULL, NULL);
        if (nready == -1) {
            perror("select");
        } else if (nready == 0) {
            continue;
        }

        // check if a new client is connecting
        if (FD_ISSET(listenfd, &rset)) {
            printf("A new client is connecting\n");
            clientfd = accept_connection(listenfd, &q);

            FD_SET(clientfd, &allset);
            if (clientfd > maxfd) {
                maxfd = clientfd;
            }
            printf("Connection from %s\n", inet_ntoa(q.sin_addr));
            add_client(&new_clients, clientfd, q.sin_addr);
            char *greeting = WELCOME_MSG;
            if (write(clientfd, greeting, strlen(greeting)) == -1) {
                fprintf(stderr, 
                    "Write to client %s failed\n", inet_ntoa(q.sin_addr));
                remove_client(&new_clients, clientfd);
            }
        }

        // Check which other socket descriptors have something ready to read.
        // The reason we iterate over the rset descriptors at the top level and
        // search through the two lists of clients each time is that it is
        // possible that a client will be removed in the middle of one of the
        // operations. This is also why we call break after handling the input.
        // If a client has been removed, the loop variables may no longer be 
        // valid.
        int cur_fd, handled;
        for (cur_fd = 0; cur_fd <= maxfd; cur_fd++) {
            if (FD_ISSET(cur_fd, &rset)) {
                handled = 0;

                // Check if any new clients are entering their names
                for (p = new_clients; p != NULL; p = p->next) {
                    if (cur_fd == p->fd) {
                        // handle input from a new client who has not yet
                        // entered an acceptable name
                        int read_status = read_client_buffer(p);
                        if (read_status == 0) {
                        	int handle_status = handle_new_client(p, &new_clients, &active_clients);
                        	// if the entered username is valid, activate the client
                        	if (handle_status == 0) {
                        		activate_client(p, &active_clients, &new_clients);
                        	}
						}
						// remove the client from new_clients list and close it if read call
						//	on its scoket fails
						else {
							fprintf(stderr, "Read from the client buffer failed\n");
							remove_client(&new_clients, p->fd);
						}
						handled = 1;
                        break;
                    }
                }

                if (!handled) {
                    // Check if this socket descriptor is an active client
                    for (p = active_clients; p != NULL; p = p->next) {
                        if (cur_fd == p->fd) {
                            // handle input from an active client
                            int read_status = read_client_buffer(p);
                            // if the input is read successfully, handle the input commands
                            if (read_status == 0) {
                        		handle_active_client(p, &active_clients);
							}
							// remove the client from new_clients list and close it if read call
							//	on its scoket fails
							else {
								char *username = p->username;
								announce_goodbye(&active_clients, username);
								fprintf(stderr, "Read from the client buffer failed\n");
								remove_client(&active_clients, p->fd);
							}
                            break;
                        }
                    }
                }
            }
        }
    }
    return 0;
}
