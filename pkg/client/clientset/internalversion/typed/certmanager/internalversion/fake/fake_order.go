/*
Copyright 2019 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	certmanager "github.com/jetstack/cert-manager/pkg/apis/certmanager"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeOrders implements OrderInterface
type FakeOrders struct {
	Fake *FakeCertmanager
	ns   string
}

var ordersResource = schema.GroupVersionResource{Group: "certmanager.k8s.io", Version: "", Resource: "orders"}

var ordersKind = schema.GroupVersionKind{Group: "certmanager.k8s.io", Version: "", Kind: "Order"}

// Get takes name of the order, and returns the corresponding order object, and an error if there is any.
func (c *FakeOrders) Get(name string, options v1.GetOptions) (result *certmanager.Order, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(ordersResource, c.ns, name), &certmanager.Order{})

	if obj == nil {
		return nil, err
	}
	return obj.(*certmanager.Order), err
}

// List takes label and field selectors, and returns the list of Orders that match those selectors.
func (c *FakeOrders) List(opts v1.ListOptions) (result *certmanager.OrderList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(ordersResource, ordersKind, c.ns, opts), &certmanager.OrderList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &certmanager.OrderList{ListMeta: obj.(*certmanager.OrderList).ListMeta}
	for _, item := range obj.(*certmanager.OrderList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested orders.
func (c *FakeOrders) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(ordersResource, c.ns, opts))

}

// Create takes the representation of a order and creates it.  Returns the server's representation of the order, and an error, if there is any.
func (c *FakeOrders) Create(order *certmanager.Order) (result *certmanager.Order, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(ordersResource, c.ns, order), &certmanager.Order{})

	if obj == nil {
		return nil, err
	}
	return obj.(*certmanager.Order), err
}

// Update takes the representation of a order and updates it. Returns the server's representation of the order, and an error, if there is any.
func (c *FakeOrders) Update(order *certmanager.Order) (result *certmanager.Order, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(ordersResource, c.ns, order), &certmanager.Order{})

	if obj == nil {
		return nil, err
	}
	return obj.(*certmanager.Order), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeOrders) UpdateStatus(order *certmanager.Order) (*certmanager.Order, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(ordersResource, "status", c.ns, order), &certmanager.Order{})

	if obj == nil {
		return nil, err
	}
	return obj.(*certmanager.Order), err
}

// Delete takes name of the order and deletes it. Returns an error if one occurs.
func (c *FakeOrders) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(ordersResource, c.ns, name), &certmanager.Order{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeOrders) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(ordersResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &certmanager.OrderList{})
	return err
}

// Patch applies the patch and returns the patched order.
func (c *FakeOrders) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *certmanager.Order, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(ordersResource, c.ns, name, pt, data, subresources...), &certmanager.Order{})

	if obj == nil {
		return nil, err
	}
	return obj.(*certmanager.Order), err
}