# change-reconciler

The CRD is available at `config/crd/bases`

Install by

`kubectl apply -f ./config/crd/bases/turbonomic.kubeturbo.io_changerequests.yaml`

A sample `ChangeRequest` resource yaml is at `config/samples`

Create by

`kubectl apply -f ./config/samples/turbonomic_v1alpha1_changerequest.yaml`


Alternatively use `Makefile`

`make install` will generate a new CRD with updates (if any) and install it to the current kubectl context
