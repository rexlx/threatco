from locust import HttpUser, TaskSet, task, between

class MyUser(HttpUser):
    wait_time = between(2, 6)
    def on_start(self):
        self.client.headers = {"Authorization": "admin@aol.com:hXvJXf/bWzFNy/U8fvO5MfOt61HrEXyLvljiX3Ss/nU="}

    @task
    def main_test(self):
        self.client.get("/user")
        self.client.get("/events/fake")
