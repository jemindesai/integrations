import types
import tasks

tasks_lst = [getattr(tasks, a) for a in dir(tasks) 
				if isinstance(getattr(tasks, a), types.FunctionType)]

def execute_task(task_name, inputs):
	for task in tasks_lst:
		if task.name == task_name:
			return task(inputs)

