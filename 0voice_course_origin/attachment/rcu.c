

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <pthread.h>
#include <limits.h>
#include <semaphore.h>

#include <urcu.h>

struct point {
	int x;
	int y;
};

struct point *gp;
int done = 0;
long reads = 0;


pthread_rwlock_t rwlock;
pthread_mutex_t mutex;
pthread_spinlock_t spinlock;
sem_t sem;

void *timer(void *arg) {

	struct timespec ts, ts2;
	timespec_get(&ts, TIME_UTC);

	while (!done) {

		sleep(1);
		timespec_get(&ts2, TIME_UTC);

		time_t sec = ts2.tv_sec - ts.tv_sec;

		printf("reads: %ld, %ld K reads/sec\n", reads, (reads/sec)/1000);

	}

}

void *updater(void *arg) {

	struct point *p;
	struct point *old;

	int i = 0;
	for (i = 0;i < INT_MAX;i ++) {

		p = malloc(sizeof(struct point));

		p->x = i;
		p->y = i+1;

		old = gp;
#if 0
		gp = p;

#elif 0
		pthread_rwlock_wrlock(&rwlock);
		gp = p;
		pthread_rwlock_unlock(&rwlock);

#elif 0

		pthread_mutex_lock(&mutex);
		gp = p;
		pthread_mutex_unlock(&mutex);

#elif 0

		pthread_spin_lock(&spinlock);
		gp = p;
		pthread_spin_unlock(&spinlock);

#elif 1

		rcu_assign_pointer(gp, p);
		synchronize_rcu();

#else

		sem_wait(&sem);
		gp = p;
		sem_post(&sem);

#endif
		free(old);
		
	}

}

void *reader(void *arg) {

	rcu_register_thread(); //urcu

	while (!done) {

		int x, y;
#if 0
		x = gp->x;
		y = gp->y;
#elif 0
		pthread_rwlock_rdlock(&rwlock);
		x = gp->x;
		y = gp->y;
		pthread_rwlock_unlock(&rwlock);

#elif 0

		pthread_mutex_lock(&mutex);
		x = gp->x;
		y = gp->y;
		pthread_mutex_unlock(&mutex);

#elif 0

		pthread_spin_lock(&spinlock);
		x = gp->x;
		y = gp->y;
		pthread_spin_unlock(&spinlock);

#elif 1

		rcu_read_lock();

		struct point *p = rcu_dereference(gp);
		x = p->x;
		y = p->y;

		rcu_read_unlock();

#else

		sem_wait(&sem);
		x = gp->x;
		y = gp->y;
		sem_post(&sem);

#endif
		reads ++;

		if (y != x+1) {
			printf("Error: x:%d, y:%d\n", x, y);
			done = 1;
			break;
		}

	}

	rcu_unregister_thread();

	exit(1);
}


int main() {

	pthread_t tid[3];

	pthread_rwlock_init(&rwlock, NULL);
	pthread_mutex_init(&mutex, NULL);
	pthread_spin_init(&spinlock, PTHREAD_PROCESS_SHARED);
	sem_init(&sem, 0, 1);

	rcu_init(); // rcu 

	gp = malloc(sizeof(struct point));
	gp->x = 1;
	gp->y = 2;

	pthread_create(&tid[0], NULL, updater, NULL);
	pthread_create(&tid[1], NULL, reader, NULL);
	pthread_create(&tid[2], NULL, timer, NULL);

	int i = 0;
	for (i = 0;i < 3;i ++) {
		pthread_join(tid[i], NULL);
	}

	free(gp);
}


