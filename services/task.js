const settings = require("../config/config");
const { getRandomNumber, sleep } = require("../utils/utils");

class TasksSv {
  constructor({ log, makeRequest, token }) {
    this.log = log;
    this.makeRequest = makeRequest;
    this.token = token;
  }

  async getTasks() {
    return this.makeRequest(`${settings.BASE_URL}/challenges?mode=user`, "get");
  }

  async doTask(id) {
    return this.makeRequest(`${settings.BASE_URL}/challenges/attempt`, "post", { id });
  }

  async claimTask(id) {
    return this.makeRequest(`${settings.BASE_URL}/challenges/verify`, "post", { id });
  }

  async handleTasks() {
    this.log(`Checking tasks`);
    const resGet = await this.getTasks();
    if (!resGet.success) return;
    const claimable = resGet.data.filter((t) => t.status !== "completed" && t.published);
    if (claimable.length == 0) return this.log(`No task available to do`, "warning");
    for (const t of claimable) {
      let taskStatus = t.status;
      if (taskStatus == "incomplete") {
        const resDo = await this.doTask(t.id);
        if (resDo.success) {
          this.log(`Completed task ${t.title} success`, "success");
          taskStatus = "pending";
          await sleep(5);
        }
      }

      if (taskStatus == "pending") {
        const resClaim = await this.claimTask(t.id);
        if (resClaim.success) {
          this.log(`Claimed task ${t.title} success`, "success");
        } else {
          this.log(`Claimed task ${t.title} failed | ${JSON.stringify(resClaim)}`, "warning");
        }
        await sleep(1);
      }
    }
  }
}

module.exports = TasksSv;
