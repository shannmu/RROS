use alloc::rc::Rc;
use core::{borrow::BorrowMut, cell::RefCell};

use crate::factory::RrosElement;
use kernel::{
    bindings, container_of,
    irq_work::IrqWork,
    pr_debug,
    workqueue::{new_work, impl_has_work, WorkItem, Work, Queue},
    prelude::*,
    macros::pin_data,
};

#[pin_data]
pub struct RrosWork {
    irq_work: IrqWork,
    #[pin]
    wq_work: Work<RrosWork>,
    wq: Queue,
    pub handler: Option<fn(arg: &mut RrosWork) -> i32>,
    // element : Rc<RefCell<RrosElement>>
    element: Option<Rc<RefCell<RrosElement>>>,
}

impl_has_work! {
    impl HasWork<Self> for RrosWork { self.wq_work }
}

impl WorkItem for RrosWork {
    type Pointer = Arc<RrosWork>;

    fn run(this: Arc<RrosWork>) {
        this.as_ref().handler(this.borrow_mut());
    }
}

unsafe extern "C" fn do_irq_work(irq_work: *mut IrqWork) {
    let work = container_of!(irq_work, RrosWork, irq_work) as *mut RrosWork;
    if (*work).wq.enqueue((*work).wq_work) && (*work).element.is_some()
    {
        pr_debug!("uncompleted rros_put_element()");
    }
    // TODO: rros_put_element is not implemented
    // if unsafe{rust_helper_queue_work((*work).wq,&mut (*work).wq_work)} && unsafe{(*)}
    // if (!queue_work(work->wq, &work->wq_work) && work->element)
    // rros_put_element(work->element);
}

impl RrosWork {
    pub const fn new() -> Self {
        unsafe {
            core::mem::transmute::<[u8; core::mem::size_of::<Self>()], Self>(
                [0; core::mem::size_of::<Self>()],
            )
        }
        // RrosWork{
        //     element : None,
        //     // element: Rc::try_new(RefCell::new(RrosElement::new().unwrap())).unwrap(),
        //     handler : None,
        //     wq : core::ptr::null_mut(),
        //     wq_work : bindings::work_struct{
        //         data : bindings::atomic64_t { counter: 0 },
        //         entry : bindings::list_head{
        //             next : core::ptr::null_mut(),
        //             prev : core::ptr::null_mut(),
        //         },
        //         // func : Some(0 as extern "C" fn(*mut bindings::work_struct)),
        //         func: None
        //     },
        //     irq_work : IrqWork::new()
        // }
    }
    pub fn init(&mut self, handler: fn(arg: &mut RrosWork) -> i32) {
        let _ret = self.irq_work.init_irq_work(do_irq_work);
        self.wq_work = new_work!("RrosWork::wq_work");
        self.handler = Some(handler);
        self.element = Some(Rc::try_new(RefCell::new(RrosElement::new().unwrap())).unwrap());
    }
    pub fn init_safe(
        &mut self,
        handler: fn(arg: &mut RrosWork) -> i32,
        element: Rc<RefCell<RrosElement>>,
    ) {
        let _ret = self.irq_work.init_irq_work(do_irq_work);
        self.wq_work = new_work!("RrosWork::wq_work");
        self.handler = Some(handler);
        self.element = Some(element);
    }
    pub fn call_inband_from(&mut self, wq: *mut bindings::workqueue_struct) {
        unsafe{ 
            self.wq = Queue::from_raw(wq)
        };
        // TODO: rros_put_element is not implemented
        // if (work->element)
        if self.element.is_some() {
            pr_debug!("uncompleted rros_get_element()");
        }
        // rros_get_element(work->element);
        if self.irq_work.irq_work_queue().is_err() && self.element.is_some() {
            pr_debug!("uncompleted rros_put_element()")
        }
        // if (!irq_work_queue(&work->irq_work) && work->element)
        // rros_put_element(work->element);
        // unsafe{rust_helper_queue_work(wq,&mut self.wq_work)};
    }

    #[inline]
    pub fn call_inband(&mut self) {
        self.call_inband_from(unsafe { bindings::system_wq });
    }
}
