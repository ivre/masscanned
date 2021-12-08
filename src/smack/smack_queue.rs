pub struct SmackQueue<T> {
    queue: Vec<T>,
}

impl<T> SmackQueue<T> {
    pub fn new() -> Self {
        SmackQueue { queue: Vec::new() }
    }
    pub fn enqueue(&mut self, data: T) {
        self.queue.push(data);
    }
    pub fn dequeue(&mut self) -> T {
        self.queue.remove(0)
    }
    pub fn has_more_items(&self) -> bool {
        !self.queue.is_empty()
    }
}
